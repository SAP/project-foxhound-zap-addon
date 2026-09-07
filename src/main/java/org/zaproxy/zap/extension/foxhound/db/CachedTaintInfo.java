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

import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;

/**
 * Wrapper for TaintInfo objects stored in the memory cache. Tracks access time for LRU eviction
 * policy.
 */
class CachedTaintInfo {
    private final TaintInfo taintInfo;
    private volatile long lastAccessTime;

    /**
     * Create a new cached TaintInfo entry.
     *
     * @param taintInfo The TaintInfo to cache
     */
    public CachedTaintInfo(TaintInfo taintInfo) {
        this.taintInfo = taintInfo;
        this.lastAccessTime = System.currentTimeMillis();
    }

    /**
     * Get the TaintInfo and update the access timestamp.
     *
     * @return The cached TaintInfo
     */
    public TaintInfo getTaintInfo() {
        this.lastAccessTime = System.currentTimeMillis();
        return taintInfo;
    }

    /**
     * Get the last access time without updating it.
     *
     * @return Timestamp of last access in milliseconds
     */
    public long getLastAccessTime() {
        return lastAccessTime;
    }
}
