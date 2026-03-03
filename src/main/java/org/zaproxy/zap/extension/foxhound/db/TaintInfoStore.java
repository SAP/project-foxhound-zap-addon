/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.foxhound.db;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.db.Database;
import org.zaproxy.zap.extension.foxhound.FoxhoundEventPublisher;
import org.zaproxy.zap.extension.foxhound.taint.TaintDeserializer;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;

/**
 * Storage for TaintInfo objects with database persistence and LRU memory caching. This class
 * maintains a two-tier architecture: - Tier 1: Hot LRU cache in memory for fast access - Tier 2:
 * Complete dataset in database for persistence
 *
 * <p>All additions are immediately persisted to the database (write-through cache). Items are
 * loaded from the database on-demand when not in the memory cache.
 */
public class TaintInfoStore {
    private static final Logger LOGGER = LogManager.getLogger(TaintInfoStore.class);
    private static final int DEFAULT_CACHE_SIZE = 1000;

    private final Map<Integer, CachedTaintInfo> memoryCache = new ConcurrentHashMap<>();
    private final TaintInfoTable dbTable;
    private final AtomicInteger nextId = new AtomicInteger(0);
    private final int maxCacheSize;
    private final ReentrantReadWriteLock cacheLock = new ReentrantReadWriteLock();
    private boolean initialized = false;

    public TaintInfoStore() {
        this(DEFAULT_CACHE_SIZE);
    }

    public TaintInfoStore(int maxCacheSize) {
        this.maxCacheSize = maxCacheSize;
        this.dbTable = new TaintInfoTable();
    }

    /**
     * Initialize the database and prepare the store for use.
     *
     * @param database The ZAP Database instance
     */
    public void init(Database database) {
        try {
            // Register the table as a database listener
            database.addDatabaseListener(dbTable);

            // The table will be initialized automatically via reconnect() callback
            // when the database is opened

            // Load max ID if possible
            loadMaxIdFromDb();

            // Load existing data from database
            loadFromDatabase();

            initialized = true;
            LOGGER.info(
                    "TaintInfoStore initialized with database persistence ({} items loaded)",
                    memoryCache.size());
        } catch (Exception e) {
            LOGGER.error("Failed to initialize database, continuing with in-memory only mode", e);
            initialized = false;
        }
    }

    /**
     * Add a TaintInfo to the store. Immediately persists to database and adds to memory cache.
     *
     * @param taintInfo The TaintInfo to add
     */
    public void addTaintInfo(TaintInfo taintInfo) {
        try {
            // Assign ID if needed
            if (taintInfo.getId() < 0) {
                taintInfo.setId(nextId.getAndIncrement());
            }

            // Persist to database (write-through cache)
            if (initialized) {
                try {
                    dbTable.insert(taintInfo);
                } catch (SQLException e) {
                    LOGGER.error("Failed to persist TaintInfo to database", e);
                    // Continue with memory cache even if DB fails (graceful degradation)
                }
            }

            // Add to memory cache
            cacheLock.writeLock().lock();
            try {
                memoryCache.put(taintInfo.getId(), new CachedTaintInfo(taintInfo));
                evictIfNeeded();
            } finally {
                cacheLock.writeLock().unlock();
            }

        } finally {
            // Always publish event
            FoxhoundEventPublisher.publishEvent(
                    FoxhoundEventPublisher.TAINT_INFO_CREATED, taintInfo, null);
        }
    }

    /** Clear all TaintInfo from both memory cache and database. */
    public void clearAll() {
        // Clear database
        if (initialized) {
            try {
                dbTable.deleteAll();
            } catch (SQLException e) {
                LOGGER.error("Failed to clear database", e);
            }
        }

        // Clear memory cache
        cacheLock.writeLock().lock();
        try {
            memoryCache.clear();
        } finally {
            cacheLock.writeLock().unlock();
        }

        FoxhoundEventPublisher.publishClearEvent();
    }

    /**
     * Get a TaintInfo by ID. Checks memory cache first, then loads from database if needed.
     *
     * @param id The TaintInfo ID
     * @return The TaintInfo or null if not found
     */
    public TaintInfo getTaintInfo(int id) {
        // Check memory cache first
        cacheLock.readLock().lock();
        try {
            CachedTaintInfo cached = memoryCache.get(id);
            if (cached != null) {
                return cached.getTaintInfo(); // Updates access time
            }
        } finally {
            cacheLock.readLock().unlock();
        }

        // Not in cache, try loading from database
        if (initialized) {
            try {
                TaintInfo fromDb = dbTable.read(id);
                if (fromDb != null) {
                    // Add to cache
                    cacheLock.writeLock().lock();
                    try {
                        memoryCache.put(id, new CachedTaintInfo(fromDb));
                        evictIfNeeded();
                    } finally {
                        cacheLock.writeLock().unlock();
                    }
                    return fromDb;
                }
            } catch (SQLException e) {
                LOGGER.error("Failed to load TaintInfo from database", e);
            }
        }

        return null;
    }

    /**
     * Get filtered TaintInfo objects. Uses database query for efficient filtering.
     *
     * @param filter The filter to apply
     * @return List of matching TaintInfo objects
     */
    public List<TaintInfo> getFilteredTaintInfos(TaintInfoFilter filter) {
        if (initialized) {
            try {
                // Use database query for filtering
                return dbTable.readFiltered(filter);
            } catch (SQLException e) {
                LOGGER.error("Failed to filter TaintInfo from database", e);
                // Fallback to in-memory filtering
            }
        }

        // Fallback: filter from memory cache
        return fallbackMemoryFilter(filter);
    }

    /**
     * Deserialize a JSON string and add the TaintInfo to the store.
     *
     * @param s JSON string
     */
    public void deserializeAndAddTaintInfo(String s) {
        TaintInfo info = TaintDeserializer.deserializeTaintInfo(s);
        if (info != null) {
            addTaintInfo(info);
        }
    }

    /**
     * Evict least recently used entry if cache size exceeds maximum. Assumes write lock is held.
     */
    private void evictIfNeeded() {
        if (memoryCache.size() > maxCacheSize) {
            // Find LRU entry
            Map.Entry<Integer, CachedTaintInfo> lru = null;
            long oldestTime = Long.MAX_VALUE;

            for (Map.Entry<Integer, CachedTaintInfo> entry : memoryCache.entrySet()) {
                long accessTime = entry.getValue().getLastAccessTime();
                if (accessTime < oldestTime) {
                    oldestTime = accessTime;
                    lru = entry;
                }
            }

            if (lru != null) {
                memoryCache.remove(lru.getKey());
                LOGGER.debug("Evicted TaintInfo {} from cache", lru.getKey());
            }
        }
    }

    /** Load the maximum ID from database to continue ID sequence. */
    private void loadMaxIdFromDb() {
        try {
            int maxId = dbTable.getMaxId();
            nextId.set(maxId + 1);
            LOGGER.debug("Loaded max ID from database: {}", maxId);
        } catch (SQLException e) {
            LOGGER.warn("Failed to load max ID from database, starting from 0", e);
            nextId.set(0);
        }
    }

    /** Load all TaintInfo objects from the database into the memory cache on startup. */
    private void loadFromDatabase() {
        try {
            List<TaintInfo> allTaintInfos = dbTable.readAll();
            LOGGER.info("Loading {} TaintInfo objects from database", allTaintInfos.size());

            cacheLock.writeLock().lock();
            try {
                for (TaintInfo taintInfo : allTaintInfos) {
                    // Load into cache (respecting cache size limit)
                    if (memoryCache.size() >= maxCacheSize) {
                        LOGGER.debug(
                                "Cache full, stopped loading at {} items. Remaining items will be lazy-loaded.",
                                memoryCache.size());
                        break;
                    }
                    memoryCache.put(taintInfo.getId(), new CachedTaintInfo(taintInfo));
                }
            } finally {
                cacheLock.writeLock().unlock();
            }

            LOGGER.info(
                    "Loaded {} TaintInfo objects into cache ({} total in database)",
                    memoryCache.size(),
                    allTaintInfos.size());
        } catch (SQLException e) {
            LOGGER.error("Failed to load TaintInfo objects from database", e);
        }
    }

    /**
     * Fallback method to filter from memory cache when database query fails.
     *
     * @param filter The filter to apply
     * @return List of matching TaintInfo objects from memory
     */
    private List<TaintInfo> fallbackMemoryFilter(TaintInfoFilter filter) {
        List<TaintInfo> filteredList = new ArrayList<>();
        cacheLock.readLock().lock();
        try {
            for (CachedTaintInfo cached : memoryCache.values()) {
                TaintInfo info = cached.getTaintInfo();
                if (filter.matches(info)) {
                    filteredList.add(info);
                }
            }
        } finally {
            cacheLock.readLock().unlock();
        }
        return filteredList;
    }
}
