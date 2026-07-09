package com.headerfusion

import burp.api.montoya.persistence.Persistence
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.util.concurrent.ConcurrentHashMap

object HeaderStore {
    val userA = ConcurrentHashMap<String, String>()
    val userB = ConcurrentHashMap<String, String>()
    
    private val gson = Gson()
    private val typeToken = object : TypeToken<Map<String, String>>() {}.type

    fun load(persistence: Persistence) {
        try {
            val extensionData = persistence.extensionData()
            val aJson = extensionData.getString("userA_headers")
            val bJson = extensionData.getString("userB_headers")
            
            if (!aJson.isNullOrBlank()) {
                val loadedA: Map<String, String> = gson.fromJson(aJson, typeToken)
                userA.clear()
                userA.putAll(loadedA)
            }
            if (!bJson.isNullOrBlank()) {
                val loadedB: Map<String, String> = gson.fromJson(bJson, typeToken)
                userB.clear()
                userB.putAll(loadedB)
            }
        } catch (e: Exception) {
            System.err.println("Error loading HeaderStore settings: ${e.message}")
        }
    }

    fun save(persistence: Persistence) {
        try {
            val extensionData = persistence.extensionData()
            extensionData.setString("userA_headers", gson.toJson(userA))
            extensionData.setString("userB_headers", gson.toJson(userB))
        } catch (e: Exception) {
            System.err.println("Error saving HeaderStore settings: ${e.message}")
        }
    }
}
