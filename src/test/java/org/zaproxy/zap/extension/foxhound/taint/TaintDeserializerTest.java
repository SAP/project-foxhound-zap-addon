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
package org.zaproxy.zap.extension.foxhound.taint;

import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import net.sf.json.JSONException;
import org.junit.jupiter.api.Test;

class TaintDeserializerTest {

    /**
     * Helper method to load JSON from test resources
     *
     * @param resourcePath Path to resource file
     * @return JSON string content
     */
    private String loadJsonFromResource(String resourcePath) throws IOException {
        InputStream inputStream = getClass().getResourceAsStream(resourcePath);
        assertNotNull(inputStream, "Resource not found: " + resourcePath);

        InputStreamReader streamReader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
        BufferedReader bufferedReader = new BufferedReader(streamReader);

        StringBuilder sb = new StringBuilder();
        String inputStr;
        while ((inputStr = bufferedReader.readLine()) != null) {
            sb.append(inputStr);
        }

        return sb.toString();
    }

    @Test
    void testDeserializeSingleFormat() throws IOException, JSONException {
        String json =
                loadJsonFromResource(
                        "/org/zaproxy/zap/extension/foxhound/taint/single-format.json");
        TaintInfo taintInfo = TaintDeserializer.deserializeTaintInfo(json);

        assertNotNull(taintInfo);
        assertEquals(
                "https://domgo.at/cxss/example/1?payload=abcd&sp=x#12345",
                taintInfo.getLocationName());
        assertEquals("Welcome <b>12345</b>!!", taintInfo.getStr());
        assertEquals("innerHTML", taintInfo.getSinkName());
        assertEquals(1764881474542L, taintInfo.getTimeStamp());
        assertFalse(taintInfo.isSubframe());

        // Check taint ranges
        assertEquals(1, taintInfo.getTaintRanges().size());
        TaintRange range = taintInfo.getTaintRanges().get(0);
        assertEquals(11, range.getBegin());
        assertEquals(16, range.getEnd());

        // Check flow
        assertNotNull(range.getFlow());
        assertTrue(range.getFlow().size() > 0);

        // Check sink
        assertNotNull(range.getSink());
        assertEquals("innerHTML", range.getSink().getOperation());

        // Check sources
        assertNotNull(range.getSources());
        assertEquals(1, range.getSources().size());
        TaintOperation source = range.getSources().iterator().next();
        assertEquals("location.hash", source.getOperation());
    }

    @Test
    void testDeserializeFindingsFormat() throws IOException, JSONException {
        String json =
                loadJsonFromResource(
                        "/org/zaproxy/zap/extension/foxhound/taint/findings-format.json");
        TaintInfo taintInfo = TaintDeserializer.deserializeTaintInfo(json);

        // Should return the first finding
        assertNotNull(taintInfo);
        assertEquals("https://example.com/test1", taintInfo.getLocationName());
        assertEquals("Test <b>data1</b>", taintInfo.getStr());
        assertEquals("innerHTML", taintInfo.getSinkName());
    }

    @Test
    void testDeserializeAllTaintInfoSingleFormat() throws IOException, JSONException {
        String json =
                loadJsonFromResource(
                        "/org/zaproxy/zap/extension/foxhound/taint/single-format.json");
        List<TaintInfo> taintInfos = TaintDeserializer.deserializeAllTaintInfo(json);

        assertNotNull(taintInfos);
        assertEquals(1, taintInfos.size());

        TaintInfo taintInfo = taintInfos.get(0);
        assertEquals(
                "https://domgo.at/cxss/example/1?payload=abcd&sp=x#12345",
                taintInfo.getLocationName());
        assertEquals("Welcome <b>12345</b>!!", taintInfo.getStr());
        assertEquals("innerHTML", taintInfo.getSinkName());
    }

    @Test
    void testDeserializeAllTaintInfoFindingsFormat() throws IOException, JSONException {
        String json =
                loadJsonFromResource(
                        "/org/zaproxy/zap/extension/foxhound/taint/findings-format.json");
        List<TaintInfo> taintInfos = TaintDeserializer.deserializeAllTaintInfo(json);

        assertNotNull(taintInfos);
        assertEquals(2, taintInfos.size());

        // Check first finding
        TaintInfo first = taintInfos.get(0);
        assertEquals("https://example.com/test1", first.getLocationName());
        assertEquals("Test <b>data1</b>", first.getStr());
        assertEquals("innerHTML", first.getSinkName());
        assertEquals(1, first.getSources().size());
        TaintOperation firstSource = first.getSources().iterator().next();
        assertEquals("location.hash", firstSource.getOperation());

        // Check second finding
        TaintInfo second = taintInfos.get(1);
        assertEquals("https://example.com/test2", second.getLocationName());
        assertEquals("Another <script>alert(2)</script>", second.getStr());
        assertEquals("eval", second.getSinkName());
        assertEquals(1, second.getSources().size());
        TaintOperation secondSource = second.getSources().iterator().next();
        assertEquals("document.cookie", secondSource.getOperation());
    }

    @Test
    void testDeserializeEmptyFindingsArray() throws JSONException {
        String json = "{\"findings\": []}";
        TaintInfo taintInfo = TaintDeserializer.deserializeTaintInfo(json);

        assertNull(taintInfo, "Empty findings array should return null");
    }

    @Test
    void testDeserializeAllTaintInfoEmptyFindingsArray() throws JSONException {
        String json = "{\"findings\": []}";
        List<TaintInfo> taintInfos = TaintDeserializer.deserializeAllTaintInfo(json);

        assertNotNull(taintInfos);
        assertTrue(taintInfos.isEmpty(), "Empty findings array should return empty list");
    }

    @Test
    void testInvalidJsonThrowsException() {
        String invalidJson = "{invalid json";
        assertThrows(
                JSONException.class, () -> TaintDeserializer.deserializeTaintInfo(invalidJson));
    }
}
