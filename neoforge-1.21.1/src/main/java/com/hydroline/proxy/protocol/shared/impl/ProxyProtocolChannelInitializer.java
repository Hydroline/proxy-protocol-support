package com.hydroline.proxy.protocol.shared.impl;

import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import com.hydroline.proxy.protocol.shared.ProxyProtocolSupport;

/**
 * Initializes HAProxyMessageDecoder and ProxyProtocolHandler
 */
public class ProxyProtocolChannelInitializer extends ChannelInitializer<Channel> {

    private final IChannelInitializer channelInitializer;

    public ProxyProtocolChannelInitializer(IChannelInitializer channelInitializer) {
        this.channelInitializer = channelInitializer;
    }

    @Override
    protected void initChannel(Channel channel) throws Exception {
        ProxyProtocolSupport.logDebug("Initializing channel " + channel.remoteAddress());

        this.channelInitializer.invokeInitChannel(channel);
        ProxyProtocolSupport.logDebug("Proxy Protocol hook reached, installing smart detector.");
        ProxyProtocolPipelineSupport.installSmartDetector(channel.pipeline());
        ProxyProtocolSupport.logDebug("Smart detector installed for " + channel.remoteAddress());
    }
}
