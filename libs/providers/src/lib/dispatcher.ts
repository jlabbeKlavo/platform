import WebSocket from 'ws';
import fetch from 'node-fetch';
import { logger } from './logger';

let reconnectAttempt = 0;
let pingInterval: NodeJS.Timeout | undefined = undefined;
let connectionTimeout: NodeJS.Timeout | undefined = undefined;

export const dispatchOps = {
    initialize: async () => {
        if (connectionTimeout)
            clearTimeout(connectionTimeout);
        connectionTimeout = undefined;
        const hookSocket = new WebSocket(process.env['KLAVE_DISPATCH_WS']!);
        hookSocket.addEventListener('open', () => {
            hookSocket.send(process.env['KLAVE_DISPATCH_SECRET']!);
            logger.info(`Connected to dispatcher ${process.env['KLAVE_DISPATCH_WS']}`);
            reconnectAttempt = 0;
            if (connectionTimeout)
                clearTimeout(connectionTimeout);
            connectionTimeout = undefined;
            pingInterval = setInterval(() => {
                hookSocket.ping();
            }, 30000);
        });
        hookSocket.addEventListener('error', (event) => {
            logger.error(`Connection ${++reconnectAttempt} to dispatcher failed: ${event.message}`);
            if (pingInterval)
                clearInterval(pingInterval);
            pingInterval = undefined;
            if (!connectionTimeout)
                connectionTimeout = setTimeout(dispatchOps.initialize, 1000);
        });
        hookSocket.addEventListener('close', (event) => {
            logger.error(`Connection ${++reconnectAttempt} to dispatcher has been closed: ${event.code} ${event.reason}`);
            if (pingInterval)
                clearInterval(pingInterval);
            pingInterval = undefined;
            if (!connectionTimeout)
                connectionTimeout = setTimeout(dispatchOps.initialize, 1000);
        });
        hookSocket.addEventListener('message', (event) => {
            const message = JSON.parse(event.data.toString()) as any;
            // TODO: Try to not use fetch on localhost here. Also get the actual port.
            fetch('http://127.0.0.1:3333/hook', {
                method: 'POST',
                headers: {
                    ...message.headers
                },
                body: JSON.stringify(message.body)
            }).catch(reason => {
                logger.warn(`Hook passover failed: ${reason}`);
            });
        });
    }
};