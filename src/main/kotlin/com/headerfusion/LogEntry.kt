package com.headerfusion

import javax.swing.SwingUtilities
import javax.swing.table.AbstractTableModel

class LogEntry(
    val number: Int,
    val method: String,
    val path: String,
    val statusCode: Short,
    val responseBodyLength: Int,
    val responseHeaderLength: Int
)

class LogTableModel : AbstractTableModel() {
    private val entries = mutableListOf<LogEntry>()

    fun addEntry(entry: LogEntry) {
        synchronized(entries) {
            entries.add(entry)
            val index = entries.size - 1
            fireTableRowsInserted(index, index)
        }
    }

    fun clear() {
        synchronized(entries) {
            val size = entries.size
            entries.clear()
            if (size > 0) {
                fireTableRowsDeleted(0, size - 1)
            }
        }
    }

    override fun getRowCount(): Int = synchronized(entries) { entries.size }

    override fun getColumnCount(): Int = 6

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val entry = synchronized(entries) {
            if (rowIndex < entries.size) entries[rowIndex] else null
        } ?: return ""
        return when (columnIndex) {
            0 -> entry.number
            1 -> entry.method
            2 -> entry.path
            3 -> if (entry.statusCode == 0.toShort()) "" else entry.statusCode
            4 -> entry.responseBodyLength
            5 -> entry.responseHeaderLength
            else -> ""
        }
    }

    override fun getColumnName(column: Int): String {
        return when (column) {
            0 -> "#"
            1 -> "Method"
            2 -> "Path"
            3 -> "Status Code"
            4 -> "Resp Body Len"
            5 -> "Resp Header Len"
            else -> ""
        }
    }
}

object LogStore {
    val model = LogTableModel()
    private var currentNumber = 1

    fun addLog(method: String, path: String, statusCode: Short, bodyLen: Int, headerLen: Int) {
        SwingUtilities.invokeLater {
            model.addEntry(LogEntry(currentNumber++, method, path, statusCode, bodyLen, headerLen))
        }
    }

    fun clear() {
        SwingUtilities.invokeLater {
            model.clear()
            currentNumber = 1
        }
    }
}
