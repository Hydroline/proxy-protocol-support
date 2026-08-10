package com.hydroline.proxy.protocol.shared.impl;

import com.hydroline.proxy.protocol.shared.ProxyProtocolSupport;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.haproxy.HAProxyCommand;
import io.netty.handler.codec.haproxy.HAProxyMessage;
import net.minecraft.network.Connection;

import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

/**
 * Reads HAProxyMessage to set valid Player IP
 */
public class ProxyProtocolHandler extends ChannelInboundHandlerAdapter {
    private static final String[] ADDRESS_FIELD_CANDIDATES = {"address", "o", "f_129469_"};
    private static volatile Field connectionAddressField;

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        ProxyProtocolSupport.logDebug("ProxyProtocolHandler activated for " + ctx.channel().remoteAddress());
        super.channelActive(ctx);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof HAProxyMessage) {
            processHAProxyMessage(ctx, (HAProxyMessage) msg);
        } else {
            processDirectConnection(ctx, msg);
        }
    }

    private void processHAProxyMessage(ChannelHandlerContext ctx, HAProxyMessage message) {
        ProxyProtocolSupport.logDebug("HAProxyMessage received from " + ctx.channel().remoteAddress() + ", command=" + message.command());
        try {
            if (message.command() == HAProxyCommand.PROXY) {
                handleProxyCommand(ctx, message);
            } else {
                ProxyProtocolSupport.logDebug("Ignoring HAProxy command " + message.command());
            }
        } catch (Exception e) {
            ProxyProtocolSupport.exceptionLogger.accept("Failed to process HAProxyMessage.", e instanceof Exception ? (Exception) e : new RuntimeException(e));
        } finally {
            cleanupAfterMessage(ctx, message);
        }
    }

    private void processDirectConnection(ChannelHandlerContext ctx, Object msg) {
        ProxyProtocolSupport.logDebug("Non-HAProxy message received: " + msg.getClass().getSimpleName());
        if (ProxyProtocolSupport.allowDirectConnections) {
            ProxyProtocolSupport.logDebug("Allowed direct connection, removing ProxyProtocol handlers.");
            removeProxyHandlers(ctx);
            ctx.fireChannelRead(msg);
        } else {
            ProxyProtocolSupport.warnLogger.accept("Direct connection rejected because proxy protocol is required.");
            ctx.disconnect();
        }
    }

    private void handleProxyCommand(ChannelHandlerContext ctx, HAProxyMessage message) {
        final String realAddress = message.sourceAddress();
        final int realPort = message.sourcePort();
        final InetSocketAddress targetAddress = new InetSocketAddress(realAddress, realPort);

        sendNetworkManagerDebug(ctx);

        Connection connection = (Connection) ctx.channel().pipeline().get("packet_handler");
        if (connection == null) {
            ProxyProtocolSupport.warnLogger.accept("Unable to find NetworkManager in pipeline.");
            return;
        }

        ProxyProtocolSupport.logDebug("NetworkManager located, proxy address=" + connection.getRemoteAddress());
        if (ProxyProtocolSupport.whitelistMode && !ProxyProtocolSupport.whitelistedIPs.isEmpty()) {
            validateWhitelist(ctx, connection);
        }

        setConnectionAddress(connection, targetAddress);
        ProxyProtocolSupport.logDebug("Assigned proxy client address " + targetAddress + " (original proxy: " + connection.getRemoteAddress() + ").");
    }

    private void setConnectionAddress(Connection connection, SocketAddress targetAddress) {
        try {
            resolveConnectionAddressField().set(connection, targetAddress);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Unable to assign Connection.address via reflection.", e);
        }
    }

    private static Field resolveConnectionAddressField() throws NoSuchFieldException {
        Field field = connectionAddressField;
        if (field != null) {
            return field;
        }

        synchronized (ProxyProtocolHandler.class) {
            field = connectionAddressField;
            if (field != null) {
                return field;
            }

            for (String candidate : ADDRESS_FIELD_CANDIDATES) {
                try {
                    field = Connection.class.getDeclaredField(candidate);
                    field.setAccessible(true);
                    connectionAddressField = field;
                    ProxyProtocolSupport.logDebug("Resolved Connection address field via reflection: " + candidate);
                    return field;
                } catch (NoSuchFieldException ignored) {
                }
            }
        }

        throw new NoSuchFieldException("No compatible Connection address field found.");
    }

    private void validateWhitelist(ChannelHandlerContext ctx, Connection connection) {
        SocketAddress proxyAddress = connection.getRemoteAddress();
        if (proxyAddress instanceof InetSocketAddress) {
            InetSocketAddress inetProxy = (InetSocketAddress) proxyAddress;
            boolean allowed = ProxyProtocolSupport.whitelistedIPs.stream()
                    .map(matcher -> matcher.matches(inetProxy.getAddress()))
                    .reduce(false, (a, b) -> a || b);
            if (!allowed) {
                ProxyProtocolSupport.warnLogger.accept("Proxy IP " + inetProxy + " rejected by whitelist.");
                ctx.disconnect();
            } else {
                ProxyProtocolSupport.logDebug("Proxy IP " + inetProxy + " accepted by whitelist.");
            }
        } else {
            ProxyProtocolSupport.warnLogger.accept("Proxy address is not an InetSocketAddress: " + proxyAddress);
        }
    }

    private void sendNetworkManagerDebug(ChannelHandlerContext ctx) {
        if (ProxyProtocolSupport.debugMode) {
            ProxyProtocolSupport.logDebug("Pipeline handlers: " + ctx.channel().pipeline().names());
        }
    }

    private void cleanupAfterMessage(ChannelHandlerContext ctx, HAProxyMessage message) {
        try {
            message.release();
        } catch (NoSuchMethodError ignored) {
            ProxyProtocolSupport.logDebug("HAProxyMessage.release() not supported on this Netty version.");
        } catch (Exception e) {
            ProxyProtocolSupport.logDebug("Failed to release HAProxyMessage: " + e.getMessage());
        }
        ctx.pipeline().remove(this);
    }

    private void removeProxyHandlers(ChannelHandlerContext ctx) {
        if (ctx.pipeline().get(ProxyProtocolPipelineSupport.HANDLER_NAME) != null) {
            ctx.pipeline().remove(ProxyProtocolPipelineSupport.HANDLER_NAME);
        }
        if (ctx.pipeline().get(ProxyProtocolPipelineSupport.DECODER_NAME) != null) {
            ctx.pipeline().remove(ProxyProtocolPipelineSupport.DECODER_NAME);
        }
    }
}
