package com.hydroline.proxy.protocol.shared.impl;

import com.hydroline.proxy.protocol.shared.ProxyProtocolSupport;
import io.netty.channel.ChannelPipeline;

public final class ProxyProtocolPipelineSupport {
    public static final String DETECTOR_NAME = "proxy_protocol:smart-detector";
    public static final String DECODER_NAME = "proxy_protocol:haproxy-decoder";
    public static final String HANDLER_NAME = "proxy_protocol:haproxy-handler";

    private ProxyProtocolPipelineSupport() {
    }

    public static void installSmartDetector(ChannelPipeline pipeline) {
        if (!ProxyProtocolSupport.enableProxyProtocol) {
            ProxyProtocolSupport.logDebug("Proxy Protocol disabled, leaving pipeline untouched.");
            return;
        }

        if (pipeline.get(DETECTOR_NAME) != null
                || pipeline.get(DECODER_NAME) != null
                || pipeline.get(HANDLER_NAME) != null) {
            ProxyProtocolSupport.logDebug("Proxy Protocol handlers already installed, skipping duplicate installation.");
            return;
        }

        final String[] preferredAnchors = new String[] {
                "timeout",
                "read_timeout",
                "legacy_query",
                "splitter",
                "decoder",
                "packet_handler"
        };

        String anchor = null;
        for (String name : preferredAnchors) {
            if (pipeline.get(name) != null) {
                anchor = name;
                break;
            }
        }

        if (ProxyProtocolSupport.debugMode) {
            ProxyProtocolSupport.logDebug("Pipeline before detector: " + pipeline.names());
            ProxyProtocolSupport.logDebug("Selected anchor: " + (anchor == null ? "<none>" : anchor));
        }

        try {
            var detector = new SmartProxyProtocolDetector();
            if (anchor == null) {
                pipeline.addFirst(DETECTOR_NAME, detector);
            } else if ("packet_handler".equals(anchor)) {
                pipeline.addBefore(anchor, DETECTOR_NAME, detector);
            } else {
                pipeline.addAfter(anchor, DETECTOR_NAME, detector);
            }
        } catch (Exception e) {
            ProxyProtocolSupport.exceptionLogger.accept("Failed to install smart detector, falling back to addFirst.", e instanceof Exception ? (Exception) e : new RuntimeException(e));
            try {
                if (pipeline.get(DETECTOR_NAME) == null) {
                    pipeline.addFirst(DETECTOR_NAME, new SmartProxyProtocolDetector());
                }
            } catch (Exception fallbackEx) {
                ProxyProtocolSupport.warnLogger.accept("Smart detector fallback installation failed, skipping detector to keep connection alive.");
                ProxyProtocolSupport.logDebug("Fallback exception: " + fallbackEx.getMessage());
            }
        }
    }
}
