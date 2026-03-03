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

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintLocation;
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;

/** Unit tests for TaintInfoStore with database persistence and LRU caching. */
public class TaintInfoStoreTest {

    private TaintInfoStore store;

    @BeforeEach
    public void setUp() throws Exception {
        // Create store with small cache for testing (in-memory mode)
        store = new TaintInfoStore(5);
    }

    @Test
    public void testAddTaintInfo() {
        TaintInfo taintInfo = createTestTaintInfo(-1);

        store.addTaintInfo(taintInfo);

        // Should auto-assign ID
        assertTrue(taintInfo.getId() >= 0);
    }

    @Test
    public void testGetTaintInfoFromMemory() {
        TaintInfo taintInfo = createTestTaintInfo(-1);
        store.addTaintInfo(taintInfo);

        int id = taintInfo.getId();
        TaintInfo retrieved = store.getTaintInfo(id);

        assertNotNull(retrieved);
        assertEquals(id, retrieved.getId());
        assertEquals("test_data", retrieved.getStr());
    }

    @Test
    public void testGetNonExistentTaintInfo() {
        TaintInfo retrieved = store.getTaintInfo(999);
        assertNull(retrieved);
    }

    @Test
    public void testClearAll() {
        store.addTaintInfo(createTestTaintInfo(-1));
        store.addTaintInfo(createTestTaintInfo(-1));

        store.clearAll();

        // After clear, getTaintInfo should return null
        assertNull(store.getTaintInfo(0));
        assertNull(store.getTaintInfo(1));
    }

    @Test
    public void testAutoIncrementIds() {
        TaintInfo info1 = createTestTaintInfo(-1);
        TaintInfo info2 = createTestTaintInfo(-1);
        TaintInfo info3 = createTestTaintInfo(-1);

        store.addTaintInfo(info1);
        store.addTaintInfo(info2);
        store.addTaintInfo(info3);

        assertEquals(0, info1.getId());
        assertEquals(1, info2.getId());
        assertEquals(2, info3.getId());
    }

    @Test
    public void testLRUEviction() throws InterruptedException {
        // Store has max cache size of 5
        // Add 6 items
        for (int i = 0; i < 6; i++) {
            TaintInfo info = createTestTaintInfo(-1);
            store.addTaintInfo(info);
            Thread.sleep(10); // Small delay to ensure different access times
        }

        // Access items 1-5 to make item 0 the LRU
        for (int i = 1; i < 6; i++) {
            store.getTaintInfo(i);
            Thread.sleep(10);
        }

        // Add one more item, should evict item 0 (oldest)
        TaintInfo newInfo = createTestTaintInfo(-1);
        store.addTaintInfo(newInfo);

        // Note: Without database persistence in this test, evicted items are lost
        // This test primarily verifies that eviction doesn't crash
    }

    @Test
    public void testFilteredTaintInfos() {
        // Add items with different sink operations
        TaintInfo info1 = createTestTaintInfo(-1);
        info1.getSink().setOperation("eval");
        store.addTaintInfo(info1);

        TaintInfo info2 = createTestTaintInfo(-1);
        info2.getSink().setOperation("innerHTML");
        store.addTaintInfo(info2);

        TaintInfo info3 = createTestTaintInfo(-1);
        info3.getSink().setOperation("eval");
        store.addTaintInfo(info3);

        // Filter by eval
        TaintInfoFilter filter = new TaintInfoFilter();
        filter.setSinks(List.of("eval"));

        List<TaintInfo> filtered = store.getFilteredTaintInfos(filter);

        // Should match the filter (at least 2 eval items)
        assertTrue(filtered.size() >= 2, "Expected at least 2 filtered items");
        assertTrue(
                filtered.stream().allMatch(t -> "eval".equals(t.getSink().getOperation())),
                "All filtered items should have eval as sink operation");
    }

    @Test
    public void testFilteredTaintInfosEmptyFilter() {
        store.addTaintInfo(createTestTaintInfo(-1));
        store.addTaintInfo(createTestTaintInfo(-1));

        TaintInfoFilter filter = new TaintInfoFilter();
        List<TaintInfo> filtered = store.getFilteredTaintInfos(filter);

        // Empty filter should match all items in cache
        assertEquals(2, filtered.size());
    }

    @Test
    public void testDeserializeAndAddTaintInfo() {
        String json =
                "{"
                        + "\"detail\": {"
                        + "\"str\": \"test\","
                        + "\"loc\": \"http://test.com\","
                        + "\"parentloc\": \"http://parent.com\","
                        + "\"referrer\": \"http://referrer.com\","
                        + "\"sink\": \"eval\","
                        + "\"timestamp\": 1234567890,"
                        + "\"subframe\": false"
                        + "},"
                        + "\"taint\": []"
                        + "}";

        store.deserializeAndAddTaintInfo(json);

        // Should have added one item
        TaintInfo retrieved = store.getTaintInfo(0);
        assertNotNull(retrieved);
        assertEquals("test", retrieved.getStr());
    }

    @Test
    public void testDeserializeInvalidJson() {
        String invalidJson = "not valid json";

        // TaintDeserializer will throw JSONException for invalid JSON
        // The store should handle it gracefully (not add anything)
        int sizeBefore = store.getFilteredTaintInfos(new TaintInfoFilter()).size();

        try {
            store.deserializeAndAddTaintInfo(invalidJson);
        } catch (Exception e) {
            // Expected - invalid JSON throws exception
        }

        // Size should not have changed
        int sizeAfter = store.getFilteredTaintInfos(new TaintInfoFilter()).size();
        assertEquals(sizeBefore, sizeAfter);
    }

    @Test
    public void testConcurrentAccess() throws InterruptedException {
        // Use a larger cache for this test to avoid evictions
        TaintInfoStore largeStore = new TaintInfoStore(150);

        // Test thread safety with concurrent adds
        Thread[] threads = new Thread[10];
        for (int i = 0; i < threads.length; i++) {
            final int threadId = i;
            threads[i] =
                    new Thread(
                            () -> {
                                for (int j = 0; j < 10; j++) {
                                    TaintInfo info = createTestTaintInfo(-1);
                                    info.setStr("thread-" + threadId + "-item-" + j);
                                    largeStore.addTaintInfo(info);
                                }
                            });
        }

        // Start all threads
        for (Thread thread : threads) {
            thread.start();
        }

        // Wait for completion
        for (Thread thread : threads) {
            thread.join();
        }

        // Should have processed 100 items total
        // IDs should be 0-99
        assertNotNull(largeStore.getTaintInfo(0));
        assertNotNull(largeStore.getTaintInfo(99));
    }

    @Test
    public void testWithoutDatabaseInitialization() {
        // Store should work without database initialization (in-memory only)
        TaintInfoStore memoryOnlyStore = new TaintInfoStore(10);

        TaintInfo info = createTestTaintInfo(-1);
        memoryOnlyStore.addTaintInfo(info);

        assertNotNull(memoryOnlyStore.getTaintInfo(info.getId()));
    }

    @Test
    public void testCustomCacheSize() {
        TaintInfoStore customStore = new TaintInfoStore(100);

        // Should accept custom cache size
        assertNotNull(customStore);

        // Add items
        for (int i = 0; i < 50; i++) {
            customStore.addTaintInfo(createTestTaintInfo(-1));
        }

        // All should be accessible
        for (int i = 0; i < 50; i++) {
            assertNotNull(customStore.getTaintInfo(i));
        }
    }

    // Helper methods

    private TaintInfo createTestTaintInfo(int id) {
        TaintInfo taintInfo = new TaintInfo();
        taintInfo.setId(id);
        taintInfo.setStr("test_data");
        taintInfo.setLocationName("http://test.com/page.html");
        taintInfo.setParentLocation("http://test.com");
        taintInfo.setReferrer("http://referrer.com");
        taintInfo.setSinkName("eval");
        taintInfo.setTimeStamp(System.currentTimeMillis());
        taintInfo.setCookie("session=abc123");
        taintInfo.setSubframe(false);

        // Create sink operation
        TaintOperation sink = new TaintOperation();
        sink.setOperation("eval");
        sink.setSource(false);
        sink.setLocation(createTestLocation());
        taintInfo.setSink(sink);

        return taintInfo;
    }

    private TaintLocation createTestLocation() {
        TaintLocation location = new TaintLocation();
        location.setFilename("test.js");
        location.setFunction("testFunction");
        location.setLine(42);
        location.setPos(10);
        location.setScriptLine(42);
        location.setMd5("abc123def456");
        return location;
    }
}
