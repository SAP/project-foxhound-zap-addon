package org.zaproxy.zap.extension.foxhound;

import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DatabaseUnsupportedException;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;
import org.zaproxy.zap.extension.foxhound.alerts.FoxhoundAlertHelper;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundOptions;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundSeleniumProfile;
import org.zaproxy.zap.extension.foxhound.db.TaintInfoStore;
import org.zaproxy.zap.extension.foxhound.db.TaintInfoTable;
import org.zaproxy.zap.extension.foxhound.ui.FoxhoundLaunchButton;
import org.zaproxy.zap.extension.foxhound.ui.FoxhoundPanel;
import org.zaproxy.zap.extension.foxhound.ui.FoxhoundScanStatus;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;

public class ExtensionFoxhound extends ExtensionAdaptor
        implements ExampleAlertProvider, SessionChangedListener {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionFoxhound.class);

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionFoxhound";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionNetwork.class, ExtensionSelenium.class);

    private FoxhoundExportServer exportServer;
    private TaintInfoStore taintStore;
    private FoxhoundAlertHelper alertHelper;

    private FoxhoundOptions options;
    private FoxhoundSeleniumProfile seleniumProfile;
    private FoxhoundLaunchButton launchButton;
    private FoxhoundPanel foxhoundPanel;
    private FoxhoundScanStatus foxhoundScanStatus;

    // Track current session to detect session switches vs. saves
    private volatile long currentSessionId = -1;

    public ExtensionFoxhound() {
        super(NAME);
    }

    @Override
    public void init() {
        super.init();
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        // Initialize TaintInfoStore (database setup happens in databaseOpen())
        getTaintStore().init();

        // Register as session listener to clear cache on session switch
        extensionHook.addSessionListener(this);

        // Start the alert helper
        getAlertHelper();

        // Load Options
        FoxhoundOptions options = getOptions();
        extensionHook.addOptionsParamSet(options);

        // Automatically update options in the selenium profile if they are changed
        seleniumProfile = getSeleniumProfile();
        seleniumProfile.setOptions(options);

        // Start the Export Server
        ExtensionNetwork extensionNetwork =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionNetwork.class);

        getExportServer().start(extensionNetwork, getOptions(), this.getTaintStore());

        // Load GUIs
        if (hasView()) {
            extensionHook.getHookView().addMainToolBarComponent(getLaunchButton());
            extensionHook.getHookView().addStatusPanel(getFoxhoundPanel());
            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .addFooterToolbarRightComponent(getFoxhoundScanStatus().getCountLabel());
        }

        LOGGER.info(
                "Starting the Foxhound ZAP extension with {} sources and {} sinks.",
                FoxhoundConstants.ALL_SOURCES.size(),
                FoxhoundConstants.ALL_SINKS.size());
    }

    @Override
    public void databaseOpen(Database database)
            throws DatabaseException, DatabaseUnsupportedException {
        // Initialize the TaintInfoStore with database
        TaintInfoStore store = getTaintStore();

        // Get the table and register it as a database listener
        TaintInfoTable table = store.getTable();
        database.addDatabaseListener(table);

        // Explicitly trigger databaseOpen on the table to create tables
        table.databaseOpen(database.getDatabaseServer());

        // Load max ID and existing data
        store.loadMaxIdFromDb();
        store.loadFromDatabase();

        // Update current session ID (only if model is available)
        if (getModel() != null) {
            Session session = getModel().getSession();
            if (session != null) {
                currentSessionId = session.getSessionId();
                LOGGER.info(
                        "Database initialized with TaintInfo tables for session {}",
                        currentSessionId);
            } else {
                LOGGER.info("Database initialized with TaintInfo tables (no session yet)");
            }
        } else {
            LOGGER.info("Database initialized with TaintInfo tables (model not available)");
        }
    }

    @Override
    public void postInit() {
        if (seleniumProfile != null) {
            seleniumProfile.writeOptionsToProfile();
        }
    }

    @Override
    public void stop() {
        LOGGER.info("Stopping the Foxhound ZAP extension");
        getExportServer().stop();
    }

    @Override
    public void unload() {
        super.unload();

        if (hasView()) {
            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .removeFooterToolbarRightComponent(getFoxhoundScanStatus().getCountLabel());
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("foxhound.desc");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    private FoxhoundOptions getOptions() {
        if (options == null) {
            options = new FoxhoundOptions();
        }
        return options;
    }

    public FoxhoundSeleniumProfile getSeleniumProfile() {
        if (seleniumProfile == null) {
            seleniumProfile = new FoxhoundSeleniumProfile();
        }
        return seleniumProfile;
    }

    private FoxhoundLaunchButton getLaunchButton() {
        if (launchButton == null) {
            launchButton = new FoxhoundLaunchButton(getSeleniumProfile());
        }
        return launchButton;
    }

    public FoxhoundExportServer getExportServer() {
        if (exportServer == null) {
            exportServer = new FoxhoundExportServer();
        }
        return exportServer;
    }

    public TaintInfoStore getTaintStore() {
        if (taintStore == null) {
            taintStore = new TaintInfoStore();
        }
        return taintStore;
    }

    public FoxhoundAlertHelper getAlertHelper() {
        if (alertHelper == null) {
            alertHelper = new FoxhoundAlertHelper(getTaintStore());
            alertHelper.registerForEvents();
        }
        return alertHelper;
    }

    public FoxhoundPanel getFoxhoundPanel() {
        if (foxhoundPanel == null) {
            foxhoundPanel = new FoxhoundPanel(this);
            foxhoundPanel.initPanel();
            foxhoundPanel.registerForEvents();
        }
        return foxhoundPanel;
    }

    public FoxhoundScanStatus getFoxhoundScanStatus() {
        if (foxhoundScanStatus == null) {
            foxhoundScanStatus = new FoxhoundScanStatus();
        }
        return foxhoundScanStatus;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return FoxhoundAlertHelper.getExampleAlerts();
    }

    // SessionChangedListener implementation

    @Override
    public void sessionAboutToChange(Session session) {
        // Decide whether to clear the store based on session change type
        long oldSessionId = session != null ? session.getSessionId() : -1;

        // If we have a valid old session AND it matches our current session, we're just saving
        if (oldSessionId > 0 && oldSessionId == currentSessionId) {
            // Session save - preserve data
            LOGGER.info(
                    "Session {} persisting (not switching). Preserving taint data.",
                    currentSessionId);
        } else {
            // Either switching sessions, or starting a new session - clear store
            LOGGER.info(
                    "Session changing (old: {}, current: {}). Clearing taint data.",
                    oldSessionId,
                    currentSessionId);
            getTaintStore().clear();
        }
    }

    @Override
    public void sessionChanged(Session session) {
        // Update current session ID (store doesn't need to know about this)
        long newSessionId = session != null ? session.getSessionId() : -1;
        currentSessionId = newSessionId;
        LOGGER.info("Session changed to: {}", newSessionId);
    }

    @Override
    public void sessionScopeChanged(Session session) {
        // No action needed - scope changes don't affect taint data persistence
    }

    @Override
    public void sessionModeChanged(Control.Mode mode) {
        // No action needed - mode changes don't affect taint data persistence
    }
}
