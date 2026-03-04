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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.paros.ParosAbstractTable;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintLocation;
import org.zaproxy.zap.extension.foxhound.taint.TaintOperation;
import org.zaproxy.zap.extension.foxhound.taint.TaintRange;

/**
 * Database table for persisting TaintInfo objects using normalized SQL tables. Extends
 * ParosAbstractTable to integrate with ZAP's database infrastructure.
 */
public class TaintInfoTable extends ParosAbstractTable {
    private static final Logger LOGGER = LogManager.getLogger(TaintInfoTable.class);

    // Table names
    private static final String TABLE_TAINT_INFO = "TAINT_INFO";
    private static final String TABLE_TAINT_OPERATION = "TAINT_OPERATION";
    private static final String TABLE_TAINT_RANGE = "TAINT_RANGE";
    private static final String TABLE_TAINT_FLOW = "TAINT_FLOW";

    // Prepared statements
    private PreparedStatement psInsertTaintInfo;
    private PreparedStatement psInsertOperation;
    private PreparedStatement psInsertRange;
    private PreparedStatement psInsertFlow;
    private PreparedStatement psSelectById;
    private PreparedStatement psSelectAllIds;
    private PreparedStatement psDeleteAll;
    private PreparedStatement psGetMaxId;
    private PreparedStatement psSelectOperations;
    private PreparedStatement psSelectRanges;
    private PreparedStatement psSelectFlow;

    // For testing - allows direct connection access
    private Connection testConnection;

    public TaintInfoTable() {}

    @Override
    protected void reconnect(Connection conn) throws DatabaseException {
        try {
            // Close old prepared statements if they exist
            closeStatements();

            // Use provided connection for table creation
            createTables(conn);

            // Prepare statements with the same connection
            // The connection will be managed by the parent class
            prepareStatements(conn);
        } catch (SQLException e) {
            throw new DatabaseException("Failed to initialize TaintInfoTable", e);
        }
    }

    /** Close all prepared statements. */
    private void closeStatements() {
        try {
            if (psInsertTaintInfo != null) psInsertTaintInfo.close();
            if (psInsertOperation != null) psInsertOperation.close();
            if (psInsertRange != null) psInsertRange.close();
            if (psInsertFlow != null) psInsertFlow.close();
            if (psSelectById != null) psSelectById.close();
            if (psSelectAllIds != null) psSelectAllIds.close();
            if (psDeleteAll != null) psDeleteAll.close();
            if (psGetMaxId != null) psGetMaxId.close();
            if (psSelectOperations != null) psSelectOperations.close();
            if (psSelectRanges != null) psSelectRanges.close();
            if (psSelectFlow != null) psSelectFlow.close();
        } catch (SQLException e) {
            LOGGER.warn("Error closing prepared statements", e);
        }
    }

    /**
     * Set the test connection for unit testing. This allows tests to inject a connection directly,
     * bypassing the normal database infrastructure.
     *
     * @param conn The connection to use for testing
     */
    public void setTestConnection(Connection conn) {
        this.testConnection = conn;
    }

    /**
     * Override getConnection to support testing with direct connection injection. In tests,
     * testConnection will be set by reconnect(). In production, it will use parent's
     * getConnection().
     */
    @Override
    protected Connection getConnection() throws DatabaseException {
        if (testConnection != null) {
            return testConnection;
        }
        return super.getConnection();
    }

    /**
     * Check if the table has been initialized (reconnect has been called).
     *
     * @return true if prepared statements are ready
     */
    public boolean isInitialized() {
        return psInsertTaintInfo != null;
    }

    /** Create all normalized tables if they don't exist. */
    private void createTables(Connection conn) throws SQLException {
        Statement stmt = conn.createStatement();
        try {
            // Main TaintInfo table
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
                            + "subframe BOOLEAN"
                            + ")");

            // TaintOperation table (stores all operations - sources and sinks)
            stmt.execute(
                    "CREATE CACHED TABLE IF NOT EXISTS "
                            + TABLE_TAINT_OPERATION
                            + " ("
                            + "operation_id INTEGER IDENTITY PRIMARY KEY, "
                            + "taint_id INTEGER NOT NULL, "
                            + "range_id INTEGER, "
                            + "operation VARCHAR(255), "
                            + "is_source BOOLEAN, "
                            + "is_sink BOOLEAN, "
                            + "filename VARCHAR(2048), "
                            + "function VARCHAR(512), "
                            + "line INTEGER, "
                            + "pos INTEGER, "
                            + "next_line INTEGER, "
                            + "next_pos INTEGER, "
                            + "script_line INTEGER, "
                            + "md5 VARCHAR(32), "
                            + "FOREIGN KEY (taint_id) REFERENCES "
                            + TABLE_TAINT_INFO
                            + "(taint_id) ON DELETE CASCADE"
                            + ")");

            // TaintRange table
            stmt.execute(
                    "CREATE CACHED TABLE IF NOT EXISTS "
                            + TABLE_TAINT_RANGE
                            + " ("
                            + "range_id INTEGER IDENTITY PRIMARY KEY, "
                            + "taint_id INTEGER NOT NULL, "
                            + "begin_pos INTEGER, "
                            + "end_pos INTEGER, "
                            + "substring CLOB(16777216), "
                            + "FOREIGN KEY (taint_id) REFERENCES "
                            + TABLE_TAINT_INFO
                            + "(taint_id) ON DELETE CASCADE"
                            + ")");

            // TaintFlow table (flow chain ordering)
            stmt.execute(
                    "CREATE CACHED TABLE IF NOT EXISTS "
                            + TABLE_TAINT_FLOW
                            + " ("
                            + "flow_id INTEGER IDENTITY PRIMARY KEY, "
                            + "range_id INTEGER NOT NULL, "
                            + "operation_id INTEGER NOT NULL, "
                            + "flow_order INTEGER NOT NULL, "
                            + "FOREIGN KEY (range_id) REFERENCES "
                            + TABLE_TAINT_RANGE
                            + "(range_id) ON DELETE CASCADE, "
                            + "FOREIGN KEY (operation_id) REFERENCES "
                            + TABLE_TAINT_OPERATION
                            + "(operation_id) ON DELETE CASCADE"
                            + ")");

            // Create indexes
            stmt.execute(
                    "CREATE INDEX IF NOT EXISTS IDX_TAINT_TIMESTAMP ON "
                            + TABLE_TAINT_INFO
                            + "(time_stamp)");
            stmt.execute(
                    "CREATE INDEX IF NOT EXISTS IDX_TAINT_SINK_NAME ON "
                            + TABLE_TAINT_INFO
                            + "(sink_name)");
            stmt.execute(
                    "CREATE INDEX IF NOT EXISTS IDX_OP_TAINT ON "
                            + TABLE_TAINT_OPERATION
                            + "(taint_id)");
            stmt.execute(
                    "CREATE INDEX IF NOT EXISTS IDX_OP_RANGE ON "
                            + TABLE_TAINT_OPERATION
                            + "(range_id)");
            stmt.execute(
                    "CREATE INDEX IF NOT EXISTS IDX_RANGE_TAINT ON "
                            + TABLE_TAINT_RANGE
                            + "(taint_id)");
            stmt.execute(
                    "CREATE INDEX IF NOT EXISTS IDX_FLOW_RANGE ON "
                            + TABLE_TAINT_FLOW
                            + "(range_id)");

            LOGGER.debug("TaintInfo normalized tables created successfully");
        } finally {
            stmt.close();
        }
    }

    /** Prepare all SQL statements for reuse. */
    private void prepareStatements(Connection conn) throws SQLException {
        psInsertTaintInfo =
                conn.prepareStatement(
                        "INSERT INTO "
                                + TABLE_TAINT_INFO
                                + " (taint_id, str, location, parent_location, referrer, sink_name, "
                                + "time_stamp, cookie, subframe) "
                                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");

        psInsertOperation =
                conn.prepareStatement(
                        "INSERT INTO "
                                + TABLE_TAINT_OPERATION
                                + " (taint_id, range_id, operation, is_source, is_sink, "
                                + "filename, function, line, pos, next_line, next_pos, script_line, md5) "
                                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        Statement.RETURN_GENERATED_KEYS);

        psInsertRange =
                conn.prepareStatement(
                        "INSERT INTO "
                                + TABLE_TAINT_RANGE
                                + " (taint_id, begin_pos, end_pos, substring) "
                                + "VALUES (?, ?, ?, ?)",
                        Statement.RETURN_GENERATED_KEYS);

        psInsertFlow =
                conn.prepareStatement(
                        "INSERT INTO "
                                + TABLE_TAINT_FLOW
                                + " (range_id, operation_id, flow_order) "
                                + "VALUES (?, ?, ?)");

        psSelectById =
                conn.prepareStatement("SELECT * FROM " + TABLE_TAINT_INFO + " WHERE taint_id = ?");

        psSelectAllIds = conn.prepareStatement("SELECT taint_id FROM " + TABLE_TAINT_INFO);

        psDeleteAll = conn.prepareStatement("DELETE FROM " + TABLE_TAINT_INFO);

        psGetMaxId =
                conn.prepareStatement("SELECT MAX(taint_id) AS max_id FROM " + TABLE_TAINT_INFO);

        psSelectOperations =
                conn.prepareStatement(
                        "SELECT * FROM "
                                + TABLE_TAINT_OPERATION
                                + " WHERE taint_id = ? ORDER BY operation_id");

        psSelectRanges =
                conn.prepareStatement(
                        "SELECT * FROM "
                                + TABLE_TAINT_RANGE
                                + " WHERE taint_id = ? ORDER BY range_id");

        psSelectFlow =
                conn.prepareStatement(
                        "SELECT * FROM "
                                + TABLE_TAINT_FLOW
                                + " WHERE range_id = ? ORDER BY flow_order");

        LOGGER.debug("Prepared statements created successfully");
    }

    /** Insert a TaintInfo object using normalized tables. */
    public synchronized void insert(TaintInfo taintInfo) throws SQLException {
        if (taintInfo == null) {
            throw new IllegalArgumentException("TaintInfo cannot be null");
        }

        Connection conn;
        try {
            conn = getConnection();
        } catch (DatabaseException e) {
            throw new SQLException("Failed to get database connection", e);
        }

        conn.setAutoCommit(false);

        try {
            // Insert main TaintInfo
            psInsertTaintInfo.setInt(1, taintInfo.getId());
            psInsertTaintInfo.setString(2, taintInfo.getStr());
            psInsertTaintInfo.setString(3, taintInfo.getLocationName());
            psInsertTaintInfo.setString(4, taintInfo.getParentLocation());
            psInsertTaintInfo.setString(5, taintInfo.getReferrer());
            psInsertTaintInfo.setString(6, taintInfo.getSinkName());
            psInsertTaintInfo.setLong(7, taintInfo.getTimeStamp());
            psInsertTaintInfo.setString(8, taintInfo.getCookie());
            psInsertTaintInfo.setBoolean(9, taintInfo.isSubframe());
            psInsertTaintInfo.executeUpdate();

            // Insert main sink operation
            if (taintInfo.getSink() != null) {
                insertOperation(taintInfo.getId(), null, taintInfo.getSink(), false, true, conn);
            }

            // Insert source operations
            if (taintInfo.getSources() != null) {
                for (TaintOperation source : taintInfo.getSources()) {
                    insertOperation(taintInfo.getId(), null, source, true, false, conn);
                }
            }

            // Insert ranges and their operations
            if (taintInfo.getTaintRanges() != null) {
                for (TaintRange range : taintInfo.getTaintRanges()) {
                    int rangeId = insertRange(taintInfo.getId(), range, conn);

                    // Insert flow operations for this range
                    if (range.getFlow() != null) {
                        for (int i = 0; i < range.getFlow().size(); i++) {
                            TaintOperation op = range.getFlow().get(i);
                            int opId =
                                    insertOperation(
                                            taintInfo.getId(),
                                            rangeId,
                                            op,
                                            op.isSource(),
                                            false,
                                            conn);

                            // Insert flow ordering
                            psInsertFlow.setInt(1, rangeId);
                            psInsertFlow.setInt(2, opId);
                            psInsertFlow.setInt(3, i);
                            psInsertFlow.executeUpdate();
                        }
                    }
                }
            }

            conn.commit();
            LOGGER.debug("Inserted TaintInfo with ID: {}", taintInfo.getId());

        } catch (SQLException e) {
            conn.rollback();
            throw e;
        } finally {
            conn.setAutoCommit(true);
        }
    }

    /** Insert a TaintOperation and return its generated ID. */
    private int insertOperation(
            int taintId,
            Integer rangeId,
            TaintOperation op,
            boolean isSource,
            boolean isSink,
            Connection conn)
            throws SQLException {
        psInsertOperation.setInt(1, taintId);
        if (rangeId != null) {
            psInsertOperation.setInt(2, rangeId);
        } else {
            psInsertOperation.setNull(2, java.sql.Types.INTEGER);
        }
        psInsertOperation.setString(3, op.getOperation());
        psInsertOperation.setBoolean(4, isSource);
        psInsertOperation.setBoolean(5, isSink);

        TaintLocation loc = op.getLocation();
        if (loc != null) {
            psInsertOperation.setString(6, loc.getFilename());
            psInsertOperation.setString(7, loc.getFunction());
            psInsertOperation.setInt(8, loc.getLine());
            psInsertOperation.setInt(9, loc.getPos());
            psInsertOperation.setInt(10, loc.getNextLine());
            psInsertOperation.setInt(11, loc.getNextPos());
            psInsertOperation.setInt(12, loc.getScriptLine());
            psInsertOperation.setString(13, loc.getMd5());
        } else {
            for (int i = 6; i <= 13; i++) {
                psInsertOperation.setNull(i, java.sql.Types.VARCHAR);
            }
        }

        psInsertOperation.executeUpdate();
        ResultSet rs = psInsertOperation.getGeneratedKeys();
        if (rs.next()) {
            return rs.getInt(1);
        }
        throw new SQLException("Failed to get generated operation ID");
    }

    /** Insert a TaintRange and return its generated ID. */
    private int insertRange(int taintId, TaintRange range, Connection conn) throws SQLException {
        psInsertRange.setInt(1, taintId);
        psInsertRange.setInt(2, range.getBegin());
        psInsertRange.setInt(3, range.getEnd());
        psInsertRange.setString(4, range.getStr());
        psInsertRange.executeUpdate();

        ResultSet rs = psInsertRange.getGeneratedKeys();
        if (rs.next()) {
            return rs.getInt(1);
        }
        throw new SQLException("Failed to get generated range ID");
    }

    /** Read a TaintInfo by ID, reconstructing from normalized tables. */
    public synchronized TaintInfo read(int id) throws SQLException {
        psSelectById.setInt(1, id);
        ResultSet rs = psSelectById.executeQuery();

        try {
            if (!rs.next()) {
                return null;
            }

            TaintInfo taintInfo = new TaintInfo();
            taintInfo.setId(rs.getInt("taint_id"));
            taintInfo.setStr(rs.getString("str"));
            taintInfo.setLocationName(rs.getString("location"));
            taintInfo.setParentLocation(rs.getString("parent_location"));
            taintInfo.setReferrer(rs.getString("referrer"));
            taintInfo.setSinkName(rs.getString("sink_name"));
            taintInfo.setTimeStamp(rs.getLong("time_stamp"));
            taintInfo.setCookie(rs.getString("cookie"));
            taintInfo.setSubframe(rs.getBoolean("subframe"));

            // Load operations
            loadOperations(taintInfo);

            // Load ranges and their flows
            loadRanges(taintInfo);

            return taintInfo;
        } finally {
            rs.close();
        }
    }

    /** Load operations for a TaintInfo. */
    private void loadOperations(TaintInfo taintInfo) throws SQLException {
        psSelectOperations.setInt(1, taintInfo.getId());
        ResultSet rs = psSelectOperations.executeQuery();

        try {
            while (rs.next()) {
                Integer rangeId = rs.getInt("range_id");
                if (rs.wasNull()) {
                    rangeId = null;
                }

                // Only load main sink/source operations (range_id is NULL)
                if (rangeId == null) {
                    TaintOperation op = buildOperation(rs);
                    if (rs.getBoolean("is_sink")) {
                        taintInfo.setSink(op);
                    } else if (rs.getBoolean("is_source")) {
                        taintInfo.getSources().add(op);
                    }
                }
            }
        } finally {
            rs.close();
        }
    }

    /** Load ranges and their flows for a TaintInfo. */
    private void loadRanges(TaintInfo taintInfo) throws SQLException {
        psSelectRanges.setInt(1, taintInfo.getId());
        ResultSet rs = psSelectRanges.executeQuery();

        try {
            while (rs.next()) {
                TaintRange range = new TaintRange();
                int rangeId = rs.getInt("range_id");
                range.setBegin(rs.getInt("begin_pos"));
                range.setEnd(rs.getInt("end_pos"));
                range.setStr(rs.getString("substring"));

                // Load flow for this range
                loadFlow(rangeId, range);

                taintInfo.getTaintRanges().add(range);
            }
        } finally {
            rs.close();
        }
    }

    /** Load flow operations for a range. */
    private void loadFlow(int rangeId, TaintRange range) throws SQLException {
        psSelectFlow.setInt(1, rangeId);
        ResultSet flowRs = psSelectFlow.executeQuery();

        Map<Integer, TaintOperation> operations = new HashMap<>();

        Connection conn;
        try {
            conn = getConnection();
        } catch (DatabaseException e) {
            throw new SQLException("Failed to get database connection", e);
        }

        // First pass: load all operations for this range
        psSelectOperations.setInt(1, 0); // Not used
        try (Statement stmt = conn.createStatement();
                ResultSet opRs =
                        stmt.executeQuery(
                                "SELECT * FROM "
                                        + TABLE_TAINT_OPERATION
                                        + " WHERE range_id = "
                                        + rangeId)) {
            while (opRs.next()) {
                int opId = opRs.getInt("operation_id");
                TaintOperation op = buildOperation(opRs);
                operations.put(opId, op);

                if (opRs.getBoolean("is_source")) {
                    range.getSources().add(op);
                }
                if (opRs.getBoolean("is_sink")) {
                    range.setSink(op);
                }
            }
        }

        // Second pass: build flow in correct order
        try {
            while (flowRs.next()) {
                int opId = flowRs.getInt("operation_id");
                TaintOperation op = operations.get(opId);
                if (op != null) {
                    range.getFlow().add(op);
                }
            }
        } finally {
            flowRs.close();
        }
    }

    /** Build a TaintOperation from a ResultSet. */
    private TaintOperation buildOperation(ResultSet rs) throws SQLException {
        TaintOperation op = new TaintOperation();
        op.setOperation(rs.getString("operation"));
        op.setSource(rs.getBoolean("is_source"));

        TaintLocation loc = new TaintLocation();
        loc.setFilename(rs.getString("filename"));
        loc.setFunction(rs.getString("function"));
        loc.setLine(rs.getInt("line"));
        loc.setPos(rs.getInt("pos"));
        loc.setNextLine(rs.getInt("next_line"));
        loc.setNextPos(rs.getInt("next_pos"));
        loc.setScriptLine(rs.getInt("script_line"));
        loc.setMd5(rs.getString("md5"));
        op.setLocation(loc);

        return op;
    }

    /** Read all TaintInfo objects. */
    public synchronized List<TaintInfo> readAll() throws SQLException {
        List<TaintInfo> results = new ArrayList<>();
        ResultSet rs = psSelectAllIds.executeQuery();

        try {
            while (rs.next()) {
                int id = rs.getInt("taint_id");
                TaintInfo taintInfo = read(id);
                if (taintInfo != null) {
                    results.add(taintInfo);
                }
            }
        } finally {
            rs.close();
        }

        LOGGER.debug("Read {} TaintInfo records from database", results.size());
        return results;
    }

    /**
     * Read filtered TaintInfo objects using SQL WHERE clause for efficiency.
     *
     * @param filter The filter to apply
     * @return List of filtered TaintInfo objects
     */
    public synchronized List<TaintInfo> readFiltered(TaintInfoFilter filter) throws SQLException {
        // If no filters, return all
        if (filter.getActiveSinks().isEmpty() && filter.getActiveSources().isEmpty()) {
            return readAll();
        }

        Connection conn;
        try {
            conn = getConnection();
        } catch (DatabaseException e) {
            throw new SQLException("Failed to get database connection", e);
        }

        Set<Integer> matchingIds = new HashSet<>();

        // Filter by sink names (directly on TAINT_INFO table using sink_name column)
        if (!filter.getActiveSinks().isEmpty()) {
            StringBuilder sinkQuery =
                    new StringBuilder(
                            "SELECT taint_id FROM " + TABLE_TAINT_INFO + " WHERE sink_name IN (");
            for (int i = 0; i < filter.getActiveSinks().size(); i++) {
                if (i > 0) sinkQuery.append(", ");
                sinkQuery.append("?");
            }
            sinkQuery.append(")");

            try (PreparedStatement ps = conn.prepareStatement(sinkQuery.toString())) {
                int paramIndex = 1;
                for (String sink : filter.getActiveSinks()) {
                    ps.setString(paramIndex++, sink);
                }

                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        matchingIds.add(rs.getInt("taint_id"));
                    }
                }
            }

            // If sink filter exists but no matches, return empty
            if (matchingIds.isEmpty()) {
                return new ArrayList<>();
            }
        }

        // Filter by source operations (requires join with TAINT_OPERATION table)
        if (!filter.getActiveSources().isEmpty()) {
            StringBuilder sourceQuery =
                    new StringBuilder(
                            "SELECT DISTINCT taint_id FROM "
                                    + TABLE_TAINT_OPERATION
                                    + " WHERE is_source = true AND operation IN (");
            for (int i = 0; i < filter.getActiveSources().size(); i++) {
                if (i > 0) sourceQuery.append(", ");
                sourceQuery.append("?");
            }
            sourceQuery.append(")");

            Set<Integer> sourceMatchingIds = new HashSet<>();
            try (PreparedStatement ps = conn.prepareStatement(sourceQuery.toString())) {
                int paramIndex = 1;
                for (String source : filter.getActiveSources()) {
                    ps.setString(paramIndex++, source);
                }

                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        sourceMatchingIds.add(rs.getInt("taint_id"));
                    }
                }
            }

            // Intersect with sink results if both filters present
            if (!filter.getActiveSinks().isEmpty()) {
                matchingIds.retainAll(sourceMatchingIds);
            } else {
                matchingIds = sourceMatchingIds;
            }

            // If no matches, return empty
            if (matchingIds.isEmpty()) {
                return new ArrayList<>();
            }
        }

        // Load full TaintInfo objects for matching IDs
        List<TaintInfo> results = new ArrayList<>();
        for (Integer id : matchingIds) {
            TaintInfo taintInfo = read(id);
            if (taintInfo != null) {
                results.add(taintInfo);
            }
        }

        return results;
    }

    /** Delete all TaintInfo records (cascades to all related tables). */
    public synchronized void deleteAll() throws SQLException {
        int count = psDeleteAll.executeUpdate();
        LOGGER.debug("Deleted {} TaintInfo records", count);
    }

    /** Get the maximum taint ID. */
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
