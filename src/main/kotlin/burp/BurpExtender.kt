/*
 * This file is part of Insertion point visualizer for Burp Suite (https://github.com/silentsignal/burp-ipv)
 * Copyright (c) 2022 Andras Veres-Szentkiralyi
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package burp

import java.net.URL
import java.util.*

const val NAME = "Insertion point visualizer"

class BurpExtender : IBurpExtender, IScannerCheck {

    private lateinit var callbacks: IBurpExtenderCallbacks
    private lateinit var helpers: IExtensionHelpers

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        helpers = callbacks.helpers

        callbacks.setExtensionName(NAME)
        callbacks.registerScannerCheck(this)
    }

    override fun doPassiveScan(baseRequestResponse: IHttpRequestResponse?): MutableList<IScanIssue> =
            Collections.emptyList() // not relevant

    override fun doActiveScan(baseRequestResponse: IHttpRequestResponse?, insertionPoint: IScannerInsertionPoint?): MutableList<IScanIssue> {
		val markers = arrayOf(callbacks.applyMarkers(baseRequestResponse,
                Collections.singletonList(insertionPoint!!.getPayloadOffsets(
                        helpers.stringToBytes(insertionPoint.baseValue))),
                Collections.emptyList()) as IHttpRequestResponse)
        val iri = helpers.analyzeRequest(baseRequestResponse)
        return Collections.singletonList(object : IScanIssue {
            override fun getUrl(): URL = iri.url
            override fun getIssueName(): String = "Insertion point"
            override fun getIssueType(): Int = 0x08000000
            override fun getSeverity(): String = "Information"
            override fun getConfidence(): String = "Tentative"
            override fun getIssueBackground(): String? = null
            override fun getRemediationBackground(): String? = null
            override fun getRemediationDetail(): String? = null
            override fun getHttpMessages(): Array<IHttpRequestResponse> = markers
            override fun getHttpService(): IHttpService = baseRequestResponse!!.httpService
            override fun getIssueDetail(): String = "Check the related request to see where the Burp Scanner " +
                    "put an insertion point. This is not a vulnerability, just an informative issue by $NAME " +
                    "so that power users could check where the Scanner put an insertion point."
        })
    }

    override fun consolidateDuplicateIssues(existingIssue: IScanIssue?, newIssue: IScanIssue?): Int = 0
}
