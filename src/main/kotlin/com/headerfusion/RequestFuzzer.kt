package com.headerfusion

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import java.util.concurrent.Executors

object RequestFuzzer {
    private val executor = Executors.newSingleThreadExecutor()

    fun processRequest(api: MontoyaApi, event: ContextMenuEvent) {
        val selectedMessages = mutableListOf<burp.api.montoya.http.message.HttpRequestResponse>()
        
        val historySelections = event.selectedRequestResponses()
        if (historySelections != null && historySelections.isNotEmpty()) {
            selectedMessages.addAll(historySelections)
        }
        
        val editorOptional = event.messageEditorRequestResponse()
        if (editorOptional != null && editorOptional.isPresent) {
            val editorItem = editorOptional.get()
            val rr = editorItem.requestResponse()
            if (rr != null) {
                selectedMessages.add(rr)
            }
        }

        if (selectedMessages.isEmpty()) {
            return
        }

        executor.submit {
            for (message in selectedMessages) {
                try {
                    val request = message.request() ?: continue
                    val headers = request.headers() ?: continue
                    
                    val userAKeys = HeaderStore.userA.keys.toSet()
                    val modHeaders = mutableListOf<HttpHeader>()

                    for (header in headers) {
                        val isTarget = userAKeys.any { it.equals(header.name(), ignoreCase = true) }
                        if (isTarget) {
                            modHeaders.add(header)
                        }
                    }

                    if (modHeaders.isNotEmpty()) {
                        val modHeadersMap = modHeaders.associate { it.name().lowercase() to it.value() }
                        val matchingUserAKeys = HeaderStore.userA.keys.filter { it.lowercase() in modHeadersMap }
                        
                        val requestValues = modHeaders.map { it.value() }.toSet()
                        val userAValues = HeaderStore.userA.values.toSet()
                        val userBValues = HeaderStore.userB.values.toSet()

                        val isUserA = requestValues.any { it in userAValues }
                        val isUserB = requestValues.any { it in userBValues }

                        val targetUserDict = when {
                            isUserA -> HeaderStore.userB
                            isUserB -> HeaderStore.userA
                            else -> HeaderStore.userB
                        }

                        val keys = matchingUserAKeys
                        val combinations = generateCombinations(keys, modHeadersMap, targetUserDict)

                        for (comb in combinations) {
                            var newRequest = request
                            
                            // Remove headers that we want to override
                            for (header in modHeaders) {
                                newRequest = newRequest.withRemovedHeader(header.name())
                            }
                            // Add modified header combinations
                            for ((k, v) in comb) {
                                newRequest = newRequest.withHeader(k, v)
                            }
                            
                            try {
                                val response = api.http().sendRequest(newRequest)
                                val respObj = response.response()
                                val statusCode = respObj?.statusCode() ?: 0.toShort()
                                val bodyLen = respObj?.body()?.length() ?: 0
                                val headers = respObj?.headers()
                                val headerLen = if (headers != null) {
                                    headers.sumOf { it.name().length + it.value().length + 4 }
                                } else 0
                                LogStore.addLog(newRequest.method(), newRequest.path(), statusCode, bodyLen, headerLen)
                            } catch (e: Exception) {
                                api.logging().logToError("[Header Fusion] Error sending request", e)
                            }
                            Thread.sleep(1000)
                        }
                    }
                } catch (e: Exception) {
                    api.logging().logToError("[Header Fusion] General error in request fuzzer", e)
                }
            }
        }
    }

    private fun generateCombinations(
        keys: List<String>,
        modHeadersMap: Map<String, String>,
        targetUserDict: Map<String, String>
    ): List<List<Pair<String, String>>> {
        val listsOfValues = mutableListOf<List<Pair<String, String>>>()
        for (key in keys) {
            val reqVal = modHeadersMap[key.lowercase()] ?: ""
            val targetVal = targetUserDict[key] ?: ""
            
            val values = if (reqVal == targetVal) {
                listOf(Pair(key, reqVal))
            } else {
                listOf(Pair(key, reqVal), Pair(key, targetVal))
            }
            listsOfValues.add(values)
        }

        return cartesianProduct(listsOfValues)
    }

    private fun <T> cartesianProduct(lists: List<List<T>>): List<List<T>> {
        var result = listOf(emptyList<T>())
        for (list in lists) {
            result = result.flatMap { r -> list.map { el -> r + el } }
        }
        return result
    }
}
