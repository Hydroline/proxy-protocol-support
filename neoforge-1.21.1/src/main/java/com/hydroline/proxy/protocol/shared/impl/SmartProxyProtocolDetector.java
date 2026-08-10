package com.hydroline.proxy.protocol.shared.impl;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.haproxy.HAProxyMessageDecoder;
import com.hydroline.proxy.protocol.shared.ProxyProtocolSupport;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Smart detector that checks the first few bytes to determine if this is a Proxy Protocol connection
 * without blocking direct connections.
 */
public class SmartProxyProtocolDetector extends ChannelInboundHandlerAdapter {

    private static final String LEGACY_DECODER_NAME = "haproxy-decoder";
    private static final byte[] PROXY_V1_PREFIX = "PROXY ".getBytes();
    private static final byte[] PROXY_V2_PREFIX = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};
    private static final AtomicBoolean EXISTING_DECODER_WARNING_LOGGED = new AtomicBoolean();

    private boolean detected = false;

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        ProxyProtocolSupport.logDebug("Smart detector activated for " + ctx.channel().remoteAddress());
        super.channelActive(ctx);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (detected) {
            super.channelRead(ctx, msg);
            return;
        }

        long startTime = System.nanoTime();

        if (!(msg instanceof ByteBuf)) {
            ProxyProtocolSupport.logDebug("Non-ByteBuf message, passing through: " + msg.getClass().getSimpleName());
            super.channelRead(ctx, msg);
            return;
        }

        ByteBuf buffer = (ByteBuf) msg;

        if (buffer.readableBytes() < 5) {
            ProxyProtocolSupport.logDebug("Waiting for more bytes from " + ctx.channel().remoteAddress());
            super.channelRead(ctx, msg);
            return;
        }

        boolean isProxyV1 = true;
        for (int i = 0; i < PROXY_V1_PREFIX.length && i < buffer.readableBytes(); i++) {
            if (buffer.getByte(buffer.readerIndex() + i) != PROXY_V1_PREFIX[i]) {
                isProxyV1 = false;
                break;
            }
        }

        boolean isProxyV2 = false;
        if (buffer.readableBytes() >= PROXY_V2_PREFIX.length) {
            isProxyV2 = true;
            for (int i = 0; i < PROXY_V2_PREFIX.length; i++) {
                if (buffer.getByte(buffer.readerIndex() + i) != PROXY_V2_PREFIX[i]) {
                    isProxyV2 = false;
                    break;
                }
            }
        }

        detected = true;
        double detectionMs = (System.nanoTime() - startTime) / 1_000_000.0;

        if (isProxyV1 || isProxyV2) {
            ProxyProtocolSupport.logDebug("Detected Proxy Protocol " + (isProxyV1 ? "v1" : "v2") + " after " + String.format("%.2f", detectionMs) + "ms.");
            Map.Entry<String, io.netty.channel.ChannelHandler> existingDecoder = findExistingDecoder(ctx);
            if (existingDecoder != null) {
                deferToExistingDecoder(ctx, msg, existingDecoder);
                return;
            }

            ctx.pipeline()
                    .addAfter(ProxyProtocolPipelineSupport.DETECTOR_NAME, ProxyProtocolPipelineSupport.DECODER_NAME, new HAProxyMessageDecoder())
                    .addAfter(ProxyProtocolPipelineSupport.DECODER_NAME, ProxyProtocolPipelineSupport.HANDLER_NAME, new ProxyProtocolHandler())
                    .remove(this);
            ProxyProtocolSupport.logDebug("Inserted HAProxy handlers for " + ctx.channel().remoteAddress());
            super.channelRead(ctx, msg);
        } else {
            ProxyProtocolSupport.logDebug("Detected direct connection for " + ctx.channel().remoteAddress() + " after " + String.format("%.2f", detectionMs) + "ms.");
            if (ProxyProtocolSupport.allowDirectConnections) {
                ProxyProtocolSupport.logDebug("Allowing direct connection and removing detector.");
                ctx.pipeline().remove(this);
                super.channelRead(ctx, msg);
            } else {
                ProxyProtocolSupport.warnLogger.accept("Direct connection rejected because proxy protocol is required.");
                ctx.disconnect();
            }
        }
    }

    private Map.Entry<String, io.netty.channel.ChannelHandler> findExistingDecoder(ChannelHandlerContext ctx) {
        for (Map.Entry<String, io.netty.channel.ChannelHandler> entry : ctx.pipeline().toMap().entrySet()) {
            if (ProxyProtocolPipelineSupport.DECODER_NAME.equals(entry.getKey())) {
                continue;
            }

            String className = entry.getValue().getClass().getName();
            if (LEGACY_DECODER_NAME.equals(entry.getKey()) || className.endsWith(".HAProxyMessageDecoder")) {
                return entry;
            }
        }
        return null;
    }

    private void deferToExistingDecoder(
            ChannelHandlerContext ctx,
            Object msg,
            Map.Entry<String, io.netty.channel.ChannelHandler> existingDecoder) throws Exception {
        String owner = existingDecoder.getKey() + " (" + existingDecoder.getValue().getClass().getName() + ")";
        if (EXISTING_DECODER_WARNING_LOGGED.compareAndSet(false, true)) {
            ProxyProtocolSupport.warnLogger.accept("Existing HAProxy decoder detected: " + owner
                    + ". Deferring Proxy Protocol handling to the existing pipeline owner. Pipeline: "
                    + ctx.pipeline().names());
        } else {
            ProxyProtocolSupport.logDebug("Deferring Proxy Protocol handling to existing decoder " + owner + ".");
        }

        ctx.pipeline().remove(this);
        super.channelRead(ctx, msg);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        ProxyProtocolSupport.logDebug("Smart detector channel inactive: " + ctx.channel().remoteAddress());
        super.channelInactive(ctx);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        ProxyProtocolSupport.exceptionLogger.accept("Smart detector encountered an exception.", cause instanceof Exception ? (Exception) cause : new RuntimeException(cause));
        super.exceptionCaught(ctx, cause);
    }
}
