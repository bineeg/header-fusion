package com.headerfusion

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import java.awt.Component
import javax.swing.JMenuItem

class HeaderFusion : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Header Fusion")
        api.logging().logToOutput("Header Fusion v2.1 (Kotlin)\nExtension Loaded\n\nAuthors\n\t- Bineeg\n\t- Amal Thamban\n")

        // Load configuration from Burp's persistent storage
        HeaderStore.load(api.persistence())

        // Initialize UI
        val ui = HeaderFusionUI(api.persistence())
        ui.refreshAll()

        // Register custom Suite Tab
        api.userInterface().registerSuiteTab("Header Fusion", ui.mainPanel)

        // Register custom Context Menu
        api.userInterface().registerContextMenuItemsProvider(object : ContextMenuItemsProvider {
            override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
                val menuList = mutableListOf<Component>()
                val fuzzMenuItem = JMenuItem("Fuzz")
                fuzzMenuItem.addActionListener {
                    RequestFuzzer.processRequest(api, event)
                }
                menuList.add(fuzzMenuItem)
                return menuList
            }
        })
    }
}
