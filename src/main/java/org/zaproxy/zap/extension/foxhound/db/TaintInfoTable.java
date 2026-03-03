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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.paros.ParosAbstractTable;
import org.zaproxy.zap.extension.foxhound.taint.TaintDeserializer;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;

/**
 * Database table for persisting TaintInfo objects. Extends ParosAbstractTable to integrate with
 * ZAP's database infrastructure.
 */
public class TaintInfoTable extends ParosAbstractTable {
    private static final Logger LOGGER = LogManager.getLogger(TaintInfoTable.class);

    // Table name
    private static final String TABLE_TAINT_INFO = "TAINT_INFO";

    // Prepared statements
    private PreparedStatement psInsertTaintInfo;
    private PreparedStatement psSelectById;
    private PreparedStatement psSelectAll;
    private PreparedStatement psDeleteAll;
    private PreparedStatement psGetMaxId;
    private PreparedStatement psSelectBySinkName;
    private PreparedStatement psSelectByTimestamp;

    public TaintInfoTable() {}

    @Override
    protected void reconnect(Connection conn) throws DatabaseException {
        try {
            createTables(conn);
            prepareStatements(conn);
        } catch (SQLException e) {
            throw new DatabaseException("Failed to initialize TaintInfoTable", e);
        }
    }

    /**
     * Create the TAINT_INFO table if it doesn't exist.
     *
     * @param conn Database connection
     * @throws SQLException if table creation fails
     */
    private void createTables(Connection conn) throws SQLException {
        Statement stmt = conn.createStatement();
        try {
            // Main table with original JSON for fidelity
            stmt.execute(
                    "CREATE CACHED TABLE IF NOT EXISTS "
                            + TABLE_TAINT_INFO
                            + " ("
                            + "taint_id INTEGER PRIMARY KEY, "
                            + "str CLOB(16777216), "
                            + "location VARCHAR(2048), "
                            + "parent_location VARCHAR(2048), "
                            + "referrer VARCHAR(2048), "
                            + "sink_name VARCHAR(255), "
                            + "time_stamp BIGINT, "
                            + "cookie VARCHAR(1024), "
                            + "subframe BOOLEAN, "
                            + "original_json CLOB(16777216)"
                            + ")");

            // Create indexes for common query patterns
            stmt.execute(
                    "CREATE INDEX IF NOT EXISTS IDX_TAINT_TIMESTAMP ON "
                            + TABLE_TAINT_INFO
                            + "(time_stamp)");
            stmt.execute(
                    "CREATE INDEX IF NOT EXISTS IDX_TAINT_SINK_NAME ON "
                            + TABLE_TAINT_INFO
                            + "(sink_name)");

            LOGGER.debug("TaintInfoTable created successfully");
        } finally {
            stmt.close();
        }
    }

    /**
     * Prepare all SQL statements for reuse.
     *
     * @param conn Database connection
     * @throws SQLException if statement preparation fails
     */
    private void prepareStatements(Connection conn) throws SQLException {
        psInsertTaintInfo =
                conn.prepareStatement(
                        "INSERT INTO "
                                + TABLE_TAINT_INFO
                                + " (taint_id, str, location, parent_location, referrer, sink_name, "
                                + "time_stamp, cookie, subframe, original_json) "
                                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

        psSelectById =
                conn.prepareStatement(
                        "SELECT original_json FROM " + TABLE_TAINT_INFO + " WHERE taint_id = ?");

        psSelectAll = conn.prepareStatement("SELECT original_json FROM " + TABLE_TAINT_INFO);

        psDeleteAll = conn.prepareStatement("DELETE FROM " + TABLE_TAINT_INFO);

        psGetMaxId =
                conn.prepareStatement("SELECT MAX(taint_id) AS max_id FROM " + TABLE_TAINT_INFO);

        psSelectBySinkName =
                conn.prepareStatement(
                        "SELECT original_json FROM " + TABLE_TAINT_INFO + " WHERE sink_name = ?");

        psSelectByTimestamp =
                conn.prepareStatement(
                        "SELECT original_json FROM "
                                + TABLE_TAINT_INFO
                                + " WHERE time_stamp >= ? AND time_stamp <= ?");

        LOGGER.debug("Prepared statements created successfully");
    }

    /**
     * Converts a TaintInfo object to JSON string for storage.
     *
     * @param taintInfo The TaintInfo to serialize
     * @return JSON string representation
     */
    private String serializeToJson(TaintInfo taintInfo) {
        // Create a simplified JSON representation
        // In production, this should reconstruct the full Foxhound format
        JSONObject json = new JSONObject();

        JSONObject detail = new JSONObject();
        detail.put("str", taintInfo.getStr());
        detail.put("loc", taintInfo.getLocationName());
        detail.put("parentloc", taintInfo.getParentLocation());
        detail.put("referrer", taintInfo.getReferrer());
        detail.put("sink", taintInfo.getSinkName());
        detail.put("timestamp", taintInfo.getTimeStamp());
        detail.put("subframe", taintInfo.isSubframe());

        json.put("detail", detail);
        json.put("taint", new net.sf.json.JSONArray()); // Simplified for now

        return json.toString();
    }

    /**
     * Insert a TaintInfo object into the database.
     *
     * @param taintInfo The TaintInfo to persist
     * @throws SQLException if insertion fails
     */
    public synchronized void insert(TaintInfo taintInfo) throws SQLException {
        if (taintInfo == null) {
            throw new IllegalArgumentException("TaintInfo cannot be null");
        }

        // Use original JSON if available, otherwise create simplified version
        String json = taintInfo.getOriginalJson();
        if (json == null || json.isEmpty()) {
            json = serializeToJson(taintInfo);
            LOGGER.warn(
                    "TaintInfo {} has no original JSON, using simplified serialization",
                    taintInfo.getId());
        }

        psInsertTaintInfo.setInt(1, taintInfo.getId());
        psInsertTaintInfo.setString(2, taintInfo.getStr());
        psInsertTaintInfo.setString(3, taintInfo.getLocationName());
        psInsertTaintInfo.setString(4, taintInfo.getParentLocation());
        psInsertTaintInfo.setString(5, taintInfo.getReferrer());
        psInsertTaintInfo.setString(6, taintInfo.getSinkName());
        psInsertTaintInfo.setLong(7, taintInfo.getTimeStamp());
        psInsertTaintInfo.setString(8, taintInfo.getCookie());
        psInsertTaintInfo.setBoolean(9, taintInfo.isSubframe());
        psInsertTaintInfo.setString(10, json);

        psInsertTaintInfo.executeUpdate();

        LOGGER.debug("Inserted TaintInfo with ID: {}", taintInfo.getId());
    }

    /**
     * Read a TaintInfo by its ID.
     *
     * @param id The taint ID
     * @return The TaintInfo or null if not found
     * @throws SQLException if query fails
     */
    public synchronized TaintInfo read(int id) throws SQLException {
        psSelectById.setInt(1, id);
        ResultSet rs = psSelectById.executeQuery();

        try {
            if (rs.next()) {
                String json = rs.getString("original_json");
                TaintInfo taintInfo = TaintDeserializer.deserializeTaintInfo(json);
                if (taintInfo != null) {
                    taintInfo.setId(id);
                }
                return taintInfo;
            }
            return null;
        } finally {
            rs.close();
        }
    }

    /**
     * Read all TaintInfo objects from the database.
     *
     * @return List of all TaintInfo objects
     * @throws SQLException if query fails
     */
    public synchronized List<TaintInfo> readAll() throws SQLException {
        List<TaintInfo> results = new ArrayList<>();
        ResultSet rs = psSelectAll.executeQuery();

        try {
            while (rs.next()) {
                String json = rs.getString("original_json");
                try {
                    TaintInfo taintInfo = TaintDeserializer.deserializeTaintInfo(json);
                    if (taintInfo != null) {
                        results.add(taintInfo);
                    }
                } catch (Exception e) {
                    LOGGER.warn("Failed to deserialize TaintInfo", e);
                }
            }
        } finally {
            rs.close();
        }

        LOGGER.debug("Read {} TaintInfo records from database", results.size());
        return results;
    }

    /**
     * Read filtered TaintInfo objects based on filter criteria.
     *
     * @param filter The filter to apply
     * @return List of matching TaintInfo objects
     * @throws SQLException if query fails
     */
    public synchronized List<TaintInfo> readFiltered(TaintInfoFilter filter) throws SQLException {
        // If no filter criteria, return all
        if (filter.getActiveSinks().isEmpty() && filter.getActiveSources().isEmpty()) {
            return readAll();
        }

        List<TaintInfo> results = new ArrayList<>();

        // If only sink filter is specified
        if (!filter.getActiveSinks().isEmpty() && filter.getActiveSources().isEmpty()) {
            for (String sinkName : filter.getActiveSinks()) {
                psSelectBySinkName.setString(1, sinkName);
                ResultSet rs = psSelectBySinkName.executeQuery();
                try {
                    while (rs.next()) {
                        String json = rs.getString("original_json");
                        try {
                            TaintInfo taintInfo = TaintDeserializer.deserializeTaintInfo(json);
                            if (taintInfo != null && filter.matches(taintInfo)) {
                                results.add(taintInfo);
                            }
                        } catch (Exception e) {
                            LOGGER.warn("Failed to deserialize TaintInfo", e);
                        }
                    }
                } finally {
                    rs.close();
                }
            }
        } else {
            // For complex filters or source-based filtering, load all and filter in memory
            List<TaintInfo> all = readAll();
            for (TaintInfo taintInfo : all) {
                if (filter.matches(taintInfo)) {
                    results.add(taintInfo);
                }
            }
        }

        LOGGER.debug("Filtered query returned {} TaintInfo records", results.size());
        return results;
    }

    /**
     * Delete all TaintInfo records from the database.
     *
     * @throws SQLException if deletion fails
     */
    public synchronized void deleteAll() throws SQLException {
        int count = psDeleteAll.executeUpdate();
        LOGGER.debug("Deleted {} TaintInfo records", count);
    }

    /**
     * Get the maximum taint ID from the database.
     *
     * @return The maximum ID or -1 if no records exist
     * @throws SQLException if query fails
     */
    public synchronized int getMaxId() throws SQLException {
        ResultSet rs = psGetMaxId.executeQuery();
        try {
            if (rs.next()) {
                int maxId = rs.getInt("max_id");
                if (rs.wasNull()) {
                    return -1;
                }
                return maxId;
            }
            return -1;
        } finally {
            rs.close();
        }
    }
}
