package com.headerfusion

import burp.api.montoya.persistence.Persistence
import java.io.File
import javax.swing.*
import javax.swing.table.AbstractTableModel

class UserTableModel(
    private val userDict: MutableMap<String, String>,
    private val onSave: () -> Unit
) : AbstractTableModel() {
    private var keys = userDict.keys.toList()

    fun refresh() {
        keys = userDict.keys.toList()
        fireTableDataChanged()
    }

    override fun getRowCount(): Int = userDict.size

    override fun getColumnCount(): Int = 2

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        if (rowIndex >= keys.size) return ""
        val key = keys[rowIndex]
        return if (columnIndex == 0) key else userDict[key] ?: ""
    }

    override fun getColumnName(column: Int): String {
        return if (column == 0) "Header Name" else "Header Value"
    }

    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean = true

    override fun setValueAt(aValue: Any?, rowIndex: Int, columnIndex: Int) {
        if (rowIndex >= keys.size || aValue == null) return
        val newValue = aValue.toString().trim()
        val oldKey = keys[rowIndex]

        if (columnIndex == 0) {
            if (newValue.isEmpty() || newValue == oldKey) return
            val valTemp = userDict.remove(oldKey) ?: ""
            userDict[newValue] = valTemp
        } else {
            userDict[oldKey] = newValue
        }
        onSave()
        refresh()
    }

    fun removeRow(rowIndex: Int) {
        if (rowIndex >= keys.size) return
        val key = keys[rowIndex]
        userDict.remove(key)
        onSave()
        refresh()
    }
}

class HeaderFusionUI(private val persistence: Persistence) {
    val mainPanel: JPanel = JPanel()
    
    private val modelA = UserTableModel(HeaderStore.userA) { HeaderStore.save(persistence) }
    private val modelB = UserTableModel(HeaderStore.userB) { HeaderStore.save(persistence) }
    
    private val tableA = JTable(modelA)
    private val tableB = JTable(modelB)
    private val tableLogs = JTable(LogStore.model)

    init {
        mainPanel.layout = java.awt.BorderLayout()

        val buttonsPanel = JPanel()
        buttonsPanel.layout = BoxLayout(buttonsPanel, BoxLayout.X_AXIS)

        val btnAddHeaders = JButton("Add headers")
        val btnSave = JButton("Save")
        val btnLoad = JButton("Load")
        val btnClear = JButton("Clear")

        val btnMargin = java.awt.Insets(4, 10, 4, 10)
        btnAddHeaders.margin = btnMargin
        btnSave.margin = btnMargin
        btnLoad.margin = btnMargin
        btnClear.margin = btnMargin

        btnAddHeaders.addActionListener { showBatchImportDialog() }
        btnSave.addActionListener { saveToFile() }
        btnLoad.addActionListener { loadFromFile() }
        btnClear.addActionListener { clearHeaders() }

        buttonsPanel.add(btnAddHeaders)
        buttonsPanel.add(Box.createHorizontalStrut(5))
        buttonsPanel.add(btnSave)
        buttonsPanel.add(Box.createHorizontalStrut(5))
        buttonsPanel.add(btnLoad)
        buttonsPanel.add(Box.createHorizontalStrut(5))
        buttonsPanel.add(btnClear)

        // Add padding around the buttons panel
        buttonsPanel.border = BorderFactory.createEmptyBorder(10, 10, 10, 10)

        val tablesPanel = JPanel()
        tablesPanel.layout = BoxLayout(tablesPanel, BoxLayout.X_AXIS)
        tablesPanel.add(JScrollPane(tableA))
        tablesPanel.add(JScrollPane(tableB))

        val splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, tablesPanel, JScrollPane(tableLogs))
        splitPane.isOneTouchExpandable = true
        splitPane.dividerLocation = 200
        splitPane.border = BorderFactory.createEmptyBorder(0, 10, 10, 10)

        setupTableDeletion(tableA, modelA)
        setupTableDeletion(tableB, modelB)

        mainPanel.add(buttonsPanel, java.awt.BorderLayout.NORTH)
        mainPanel.add(splitPane, java.awt.BorderLayout.CENTER)
    }

    private fun setupTableDeletion(table: JTable, model: UserTableModel) {
        val popupMenu = JPopupMenu()
        val deleteItem = JMenuItem("Delete Row")
        deleteItem.addActionListener {
            val selectedRow = table.selectedRow
            if (selectedRow != -1) {
                model.removeRow(selectedRow)
            }
        }
        popupMenu.add(deleteItem)
        table.componentPopupMenu = popupMenu

        table.addKeyListener(object : java.awt.event.KeyAdapter() {
            override fun keyPressed(e: java.awt.event.KeyEvent) {
                if (e.keyCode == java.awt.event.KeyEvent.VK_DELETE) {
                    val selectedRow = table.selectedRow
                    if (selectedRow != -1) {
                        model.removeRow(selectedRow)
                    }
                }
            }
        })
    }

    private fun showBatchImportDialog() {
        val dialogPanel = JPanel()
        dialogPanel.layout = BoxLayout(dialogPanel, BoxLayout.Y_AXIS)

        dialogPanel.add(JLabel("Import Target:"))
        val userOptions = arrayOf("User A", "User B")
        val userSelect = JComboBox(userOptions)
        dialogPanel.add(userSelect)
        dialogPanel.add(Box.createVerticalStrut(10))

        dialogPanel.add(JLabel("Paste Headers (Name: Value, one per line):"))
        val txtHeaders = JTextArea(10, 40)
        txtHeaders.lineWrap = true
        dialogPanel.add(JScrollPane(txtHeaders))

        val result = JOptionPane.showConfirmDialog(
            mainPanel,
            dialogPanel,
            "Batch Import Headers",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
        )

        if (result == JOptionPane.OK_OPTION) {
            val text = txtHeaders.text
            if (!text.isNullOrBlank()) {
                val targetUser = userSelect.selectedItem as String
                val targetDict = if (targetUser == "User A") HeaderStore.userA else HeaderStore.userB
                val model = if (targetUser == "User A") modelA else modelB

                text.lineSequence().forEach { line ->
                    if (line.contains(":")) {
                        val parts = line.split(":", limit = 2)
                        if (parts.size == 2) {
                            val name = parts[0].trim()
                            val value = parts[1].trim()
                            if (name.isNotEmpty()) {
                                targetDict[name] = value
                            }
                        }
                    }
                }
                model.refresh()
                HeaderStore.save(persistence)
                JOptionPane.showMessageDialog(mainPanel, "Headers imported successfully to $targetUser.")
            }
        }
    }

    private fun saveToFile() {
        val fileChooser = JFileChooser()
        fileChooser.selectedFile = File("HeaderFusion_Config.json")
        val returnVal = fileChooser.showSaveDialog(mainPanel)

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            val selectedFile = fileChooser.selectedFile
            try {
                val config = mapOf(
                    "userA" to HeaderStore.userA,
                    "userB" to HeaderStore.userB
                )
                val gson = com.google.gson.GsonBuilder().setPrettyPrinting().create()
                selectedFile.printWriter().use { out ->
                    out.print(gson.toJson(config))
                }
                JOptionPane.showMessageDialog(
                    mainPanel,
                    "Configuration saved successfully to ${selectedFile.name}"
                )
            } catch (ex: Exception) {
                JOptionPane.showMessageDialog(
                    mainPanel,
                    "Error saving file: ${ex.message}"
                )
            }
        }
    }

    private fun loadFromFile() {
        val fileChooser = JFileChooser()
        val returnVal = fileChooser.showOpenDialog(mainPanel)
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            val selectedFile = fileChooser.selectedFile
            try {
                val jsonStr = selectedFile.readText()
                val gson = com.google.gson.Gson()
                val typeToken = object : com.google.gson.reflect.TypeToken<Map<String, Map<String, String>>>() {}.type
                val config: Map<String, Map<String, String>> = gson.fromJson(jsonStr, typeToken)
                
                val loadedA = config["userA"]
                val loadedB = config["userB"]

                if (loadedA != null && loadedB != null) {
                    HeaderStore.userA.clear()
                    HeaderStore.userA.putAll(loadedA)
                    
                    HeaderStore.userB.clear()
                    HeaderStore.userB.putAll(loadedB)

                    modelA.refresh()
                    modelB.refresh()
                    HeaderStore.save(persistence)
                    JOptionPane.showMessageDialog(
                        mainPanel,
                        "Configuration loaded successfully from ${selectedFile.name}"
                    )
                } else {
                    JOptionPane.showMessageDialog(
                        mainPanel,
                        "Invalid configuration file: 'userA' and 'userB' sections must be present.",
                        "Error",
                        JOptionPane.ERROR_MESSAGE
                    )
                }
            } catch (ex: Exception) {
                JOptionPane.showMessageDialog(
                    mainPanel,
                    "Error loading file: ${ex.message}"
                )
            }
        }
    }

    private fun clearHeaders() {
        val result = JOptionPane.showConfirmDialog(
            mainPanel,
            "Are you sure you want to clear all headers for both User A and User B?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        )

        if (result == JOptionPane.YES_OPTION) {
            HeaderStore.userA.clear()
            HeaderStore.userB.clear()
            modelA.refresh()
            modelB.refresh()
            LogStore.clear()
            HeaderStore.save(persistence)
            JOptionPane.showMessageDialog(mainPanel, "All headers and logs cleared successfully.")
        }
    }

    fun refreshAll() {
        modelA.refresh()
        modelB.refresh()
    }
}
