package ghidra.mcp;

import javax.swing.Icon;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

public class GhidraMCPPluginPackage extends PluginPackage {

    public static final String NAME = "GhidraMCP";

    public GhidraMCPPluginPackage() {
        super(NAME, ResourceManager.loadImage("images/package_green.png"),
                "Model Context Protocol integration for Ghidra",
                FEATURE_PRIORITY);
    }
}
