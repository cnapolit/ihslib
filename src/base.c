/*
 *  _____  _   _  _____  _  _  _
 * |_   _|| | | |/  ___|| |(_)| |     Steam
 *   | |  | |_| |\ `--. | | _ | |__     In-Home
 *   | |  |  _  | `--. \| || || '_ \      Streaming
 *  _| |_ | | | |/\__/ /| || || |_) |       Library
 *  \___/ \_| |_/\____/ |_||_||_.__/
 *
 * Copyright (c) 2022 Mariotaku <https://github.com/mariotaku>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "base.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "endianness.h"
#include "crypto.h"
#include "ihs_buffer.h"

static void BaseWorker(IHS_Base *base);

static void BaseUpdateSecretKey(IHS_Base *base, const uint8_t *secretKey);

static bool initialized;

void IHS_Init() {
    initialized = true;
    IHS_TimerInit();
}

void IHS_Quit() {
    IHS_TimerQuit();
    initialized = false;
}

void IHS_BaseInit(IHS_Base *base, const IHS_ClientConfig *config, IHS_BaseReceivedFunction recvCb, bool broadcast) {
    assert(base != NULL);
    assert(initialized);
    memset(base, 0, sizeof(IHS_Base));
    base->broadcast = broadcast;
    base->lock = IHS_MutexCreate();
    base->callbacks.received = recvCb;

    base->deviceId = config->deviceId;
    strncpy(base->deviceName, config->deviceName ? config->deviceName : "IHSLib", sizeof(base->deviceName) - 1);
    base->deviceName[sizeof(base->deviceName) - 1] = '\0';
    BaseUpdateSecretKey(base, config->secretKey);
}

void IHS_BaseSetSecretKey(IHS_Base *base, const uint8_t *secretKey) {
    assert(base != NULL);
    IHS_BaseLock(base);
    BaseUpdateSecretKey(base, secretKey);
    IHS_BaseUnlock(base);
}

void IHS_BaseGetSecretKey(IHS_Base *base, uint8_t *secretKey) {
    assert(base != NULL);
    IHS_BaseLock(base);
    memcpy(secretKey, base->secretKey, sizeof(base->secretKey));
    IHS_BaseUnlock(base);
}

/**
 * The device token, SymmetricEncrypt(u64le device ID), is derived from the secret key.
 */
static void BaseUpdateSecretKey(IHS_Base *base, const uint8_t *secretKey) {
    memcpy(base->secretKey, secretKey, sizeof(base->secretKey));
    uint8_t in[8];
    size_t deviceTokenLen = sizeof(base->deviceToken);
    IHS_WriteUInt64LE(in, base->deviceId);
    IHS_CryptoSymmetricEncrypt(in, 8, base->secretKey, sizeof(base->secretKey),
                               base->deviceToken, &deviceTokenLen);
}

void IHS_BaseSetLogFunction(IHS_Base *base, IHS_LogFunction *logFunction) {
    assert(base != NULL);
    IHS_BaseLock(base);
    base->callbacks.log = logFunction;
    IHS_BaseUnlock(base);
}

void IHS_BaseSetRunCallbacks(IHS_Base *base, const IHS_BaseRunCallbacks *callbacks, void *context) {
    assert(base != NULL);
    IHS_BaseLock(base);
    base->callbacks.run = callbacks;
    base->callbackContexts.run = context;
    IHS_BaseUnlock(base);
}

void IHS_BaseLog(IHS_Base *base, IHS_LogLevel level, const char *tag, const char *fmt, ...) {
    assert(base != NULL);
    if (!base->callbacks.log) return;
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, 4095, fmt, args);
    base->callbacks.log(level, tag, buf);
    va_end(args);
}

const char *IHS_LogLevelName(IHS_LogLevel level) {
    switch (level) {
        case IHS_LogLevelFatal:
            return "Fatal";
        case IHS_LogLevelError:
            return "Error";
        case IHS_LogLevelWarn:
            return "Warn";
        case IHS_LogLevelInfo:
            return "Info";
        case IHS_LogLevelDebug:
            return "Debug";
        case IHS_LogLevelVerbose:
            return "Verbose";
        default:
            return "";
    }
}

bool IHS_BaseStartWorker(IHS_Base *base, const char *name) {
    assert(base != NULL);
    IHS_BaseLock(base);
    if (base->worker != NULL) {
        IHS_BaseUnlock(base);
        return false;
    }
    // Opened here rather than on the worker, and closed only once the worker is joined: other threads send on it
    // (the timer, the caller) as soon as this returns, and a socket the worker had not opened yet dropped their
    // first sends, such as a one-off unicast discovery.
    base->socket = IHS_UDPSocketOpen(base->broadcast);
    base->worker = IHS_ThreadCreate((IHS_ThreadFunction *) BaseWorker, name, base);
    IHS_BaseLog(base, IHS_LogLevelInfo, "Worker", "Worker thread %s created", name);
    IHS_BaseUnlock(base);
    return true;
}

void IHS_BaseInterruptWorker(IHS_Base *base) {
    assert(base != NULL);
    IHS_BaseLock(base);
    if (base->interrupted) {
        IHS_BaseUnlock(base);
        return;
    }
    base->interrupted = true;
    IHS_BaseUnlock(base);
}

void IHS_BaseWaitWorker(IHS_Base *base) {
    assert(base != NULL);
    IHS_ThreadJoin(base->worker);
    base->worker = NULL;
    // Clear base->socket under the lock so any concurrent IHS_BaseSend that takes the lock after this point sees
    // NULL and bails, then close it once no in-flight send can still reference it.
    IHS_BaseLock(base);
    IHS_UDPSocket *socket = base->socket;
    base->socket = NULL;
    IHS_BaseUnlock(base);
    if (socket != NULL) {
        IHS_UDPSocketClose(socket);
    }
}

void IHS_BaseDestroy(IHS_Base *base) {
    assert(base != NULL);
    IHS_MutexDestroy(base->lock);
}

bool IHS_BaseSend(IHS_Base *base, IHS_SocketAddress address, const IHS_Buffer *data) {
    assert(base != NULL);
    // Hold base->lock across the send so IHS_BaseWaitWorker's close can't free the
    // socket out from under us. It sets socket = NULL under the same lock before
    // calling IHS_UDPSocketClose, so any send that completes here uses a live socket.
    IHS_BaseLock(base);
    bool ret = false;
    if (base->socket != NULL) {
        IHS_UDPPacket packet = {.address = address, .buffer = *data};
        ret = IHS_UDPSocketSend(base->socket, &packet);
    }
    IHS_BaseUnlock(base);
    return ret;
}

void IHS_BaseLock(IHS_Base *base) {
    assert(base != NULL);
    IHS_MutexLock(base->lock);
}

void IHS_BaseUnlock(IHS_Base *base) {
    assert(base != NULL);
    IHS_MutexUnlock(base->lock);
}

static void BaseWorker(IHS_Base *base) {
    assert(base != NULL);
    // Opened by IHS_BaseStartWorker before this thread was created, and closed by IHS_BaseWaitWorker after it is
    // joined, so it stays the same for the worker's whole life.
    IHS_UDPSocket *socket = base->socket;
    if (base->callbacks.run && base->callbacks.run->initialized) {
        base->callbacks.run->initialized(base, base->callbackContexts.run);
    }
    IHS_UDPPacket recv;
    IHS_BufferInit(&recv.buffer, 2048, 2048);
    while (!base->interrupted) {
        int ret;
        if ((ret = IHS_UDPSocketReceive(socket, &recv)) < 0) {
            IHS_BaseLog(base, IHS_LogLevelError, "Worker", "Receiving failed, worker stops: %s", strerror(errno));
            break;
        }
        if (ret) {
            base->callbacks.received(base, &recv.address, &recv.buffer);
        }
        IHS_BufferClear(&recv.buffer, false);
    }
    IHS_BufferClear(&recv.buffer, true);
    if (base->callbacks.run && base->callbacks.run->finalized) {
        base->callbacks.run->finalized(base, base->callbackContexts.run);
    }
}

