#!/usr/bin/env python
# coding: utf8

"""
    A pure python ping implementation using raw socket.


    Note that ICMP messages can only be sent from processes running as root.


    Derived from ping.c distributed in Linux's netkit. That code is
    copyright (c) 1989 by The Regents of the University of California.
    That code is in turn derived from code written by Mike Muuss of the
    US Army Ballistic Research Laboratory in December, 1983 and
    placed in the public domain. They have my thanks.

    Bugs are naturally mine. I'd be glad to hear about them. There are
    certainly word - size dependencies here.

    Copyright (c) Matthew Dixon Cowles, <http://www.visi.com/~mdc/>.
    Distributable under the terms of the GNU General Public License
    version 2. Provided with no warranties of any sort.

    Original Version from Matthew Dixon Cowles:
      -> ftp://ftp.visi.com/users/mdc/ping.py

    Rewrite by Jens Diemer:
      -> http://www.python-forum.de/post-69122.html#69122

    Rewrite by Anton Belousov / Stellarbit LLC <anton@stellarbit.com>
       -> http://github.com/stellarbit/aioping

    Revision history
    ~~~~~~~~~~~~~~~~

    November 22, 1997
    Initial hack. Doesn't do much, but rather than try to guess
    what features I (or others) will want in the future, I've only
    put in what I need now.

    December 16, 1997
    For some reason, the checksum bytes are in the wrong order when
    this is run under Solaris 2.X for SPARC but it works right under
    Linux x86. Since I don't know just what's wrong, I'll swap the
    bytes always and then do an htons().

    December 4, 2000
    Changed the struct.pack() calls to pack the checksum and ID as
    unsigned. My thanks to Jerome Poincheval for the fix.

    May 30, 2007
    little rewrite by Jens Diemer:
     -  change socket asterisk import to a normal import
     -  replace time.time() with time.clock()
     -  delete "return None" (or change to "return" only)
     -  in checksum() rename "str" to "source_string"

    March 11, 2010
    changes by Samuel Stauffer:
    - replaced time.clock with default_timer which is set to
      time.clock on windows and time.time on other systems.

    Januari 27, 2015
    Changed receive response to not accept ICMP request messages.
    It was possible to receive the very request that was sent.

    January 15, 2017
    Changes by Anton Belousov / Stellarbit LLC
    - asyncio & python 3.5+ adaptaion
    - PEP-8 code reformatting

    Last commit info:
    ~~~~~~~~~~~~~~~~~
    $LastChangedDate: $
    $Rev: $
    $Author: $
"""

import logging
import asyncio
import async_timeout
import sys
import socket
import struct
import time
import functools
import uuid
import random
import platform
import os

logger = logging.getLogger("aioping")
default_timer = time.perf_counter

if sys.platform.startswith("win"):
    if sys.version_info[0] > 3 or (sys.version_info[0] == 3 and sys.version_info[1] >= 8):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ICMP types, see rfc792 for v4, rfc4443 for v6
ICMP_ECHO_REQUEST = 8
ICMP6_ECHO_REQUEST = 128
ICMP_ECHO_REPLY = 0
ICMP6_ECHO_REPLY = 129

proto_icmp = socket.getprotobyname("icmp")
proto_icmp6 = socket.getprotobyname("ipv6-icmp")


def checksum(source_string):
    """
    RFC 1071: Checksum calculation for ICMP packets.
    :param source_string: bytes
    :return: int
    """
    if len(source_string) % 2:
        source_string += b"\x00"

    res = sum(struct.unpack("!%dH" % (len(source_string) // 2), source_string))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return ~res & 0xffff


async def receive_one_ping(my_socket, id_, timeout, expected_src_ip):
    """
    receive the ping from the socket.
    :param my_socket:
    :param id_:
    :param timeout:
    :return:
    """
    loop = asyncio.get_event_loop()

    try:
        async with async_timeout.timeout(timeout):
            while True:
                future = loop.create_future()

                def _read_ready():
                    try:
                        data, addr = my_socket.recvfrom(1024)
                        if not future.done():
                            future.set_result((data, addr))
                    except (BlockingIOError, InterruptedError):
                        pass
                    except Exception as exc:
                        if not future.done():
                            future.set_exception(exc)

                loop.add_reader(my_socket, _read_ready)
                try:
                    rec_packet, addr = await future
                finally:
                    loop.remove_reader(my_socket)

                # No IP Header when unpriviledged on Linux
                has_ip_header = (
                    (os.name != "posix")
                    or (platform.system() == "Darwin")
                    or (my_socket.type == socket.SOCK_RAW)
                )

                time_received = default_timer()

                if my_socket.family == socket.AddressFamily.AF_INET and has_ip_header:
                    offset = 20
                else:
                    offset = 0

                icmp_header = rec_packet[offset:offset + 8]

                type, code, packet_checksum, packet_id, sequence = struct.unpack(
                    "!BBHHH", icmp_header
                )

                if type != ICMP_ECHO_REPLY and type != ICMP6_ECHO_REPLY:
                    continue

                if addr[0] != expected_src_ip:
                    continue

                if not has_ip_header:
                    # When unprivileged on Linux, ICMP ID is rewrited by kernel
                    # to the source port of the socket.
                    expected_id = my_socket.getsockname()[1]
                else:
                    expected_id = id_

                if packet_id == expected_id:
                    data = rec_packet[offset + 8:offset + 8 + struct.calcsize("!d")]
                    time_sent = struct.unpack("!d", data)[0]

                    return time_received - time_sent
                else:
                    logger.debug("Received ICMP packet with id %s, but expected %s. Ignoring.", packet_id, id_)
                    # We must wait for the next packet as this one was not for us
                    continue

    except asyncio.TimeoutError:
        raise TimeoutError("Ping timeout")


def sendto_ready(packet, socket, future, dest):
    try:
        socket.sendto(packet, dest)
    except (BlockingIOError, InterruptedError):
        return  # The callback will be retried
    except Exception as exc:
        asyncio.get_event_loop().remove_writer(socket)
        future.set_exception(exc)
    else:
        asyncio.get_event_loop().remove_writer(socket)
        future.set_result(None)


async def send_one_ping(my_socket, dest_addr, id_, timeout, family):
    """
    Send one ping to the given >dest_addr<.
    :param my_socket:
    :param dest_addr:
    :param id_:
    :param timeout:
    :return:
    """
    icmp_type = ICMP_ECHO_REQUEST if family == socket.AddressFamily.AF_INET\
        else ICMP6_ECHO_REQUEST

    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    # Make a dummy header with a 0 checksum.
    header = struct.pack("!BBHHH", icmp_type, 0, 0, id_, 1)
    bytes_in_double = struct.calcsize("!d")
    data = (192 - bytes_in_double) * "Q"
    data = struct.pack("!d", default_timer()) + data.encode("ascii")

    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data)

    # Now that we have the right checksum, we put that in.
    header = struct.pack(
        "!BBHHH", icmp_type, 0, my_checksum, id_, 1
    )
    packet = header + data

    future = asyncio.get_event_loop().create_future()
    callback = functools.partial(sendto_ready, packet=packet, socket=my_socket, dest=dest_addr, future=future)
    asyncio.get_event_loop().add_writer(my_socket, callback)

    await future


async def ping(dest_addr, timeout=10, family=None):
    """
    Returns either the delay (in seconds) or raises an exception.
    :param dest_addr:
    :param timeout:
    :param family:
    """

    loop = asyncio.get_event_loop()
    info = await loop.getaddrinfo(dest_addr, 0)

    logger.debug("%s getaddrinfo result=%s", dest_addr, info)

    if family is not None:
        info = list(filter(lambda i: i[0] == family, info))

    if len(info) == 0:
        raise socket.gaierror("%s hostname not found for address family %s" % (dest_addr, family))

    resolved = random.choice(info)

    family = resolved[0]
    addr = resolved[4]

    logger.debug("%s resolved addr=%s", dest_addr, addr)

    if family == socket.AddressFamily.AF_INET:
        icmp = proto_icmp
    else:
        icmp = proto_icmp6

    try:
        my_socket = socket.socket(family, socket.SOCK_RAW, icmp)

    except OSError as e:
        if e.errno == 1 or e.errno == 13:
            # Operation not permitted or Permission denied, using SOCK_DGRAM instead:
            my_socket = socket.socket(family, socket.SOCK_DGRAM, icmp)
            logger.debug("Error using socket.SOCK_RAW: '%s'. Using socket.SOCK_DGRAM instead", e.strerror)
        else:
            raise

    try:
        my_socket.setblocking(False)

        my_id = uuid.uuid4().int & 0xFFFF

        await send_one_ping(my_socket, addr, my_id, timeout, family)
        delay = await receive_one_ping(my_socket, my_id, timeout, addr[0])
        return delay
    finally:
        my_socket.close()


async def verbose_ping(dest_addr, timeout=2, count=3, family=None):
    """
    Send >count< ping to >dest_addr< with the given >timeout< and display
    the result.
    :param dest_addr:
    :param timeout:
    :param count:
    :param family:
    """
    for i in range(count):
        delay = None

        try:
            delay = await ping(dest_addr, timeout, family)
        except TimeoutError as e:
            logger.error("%s timed out after %ss" % (dest_addr, timeout))
        except Exception as e:
            logger.error("%s failed: %s" % (dest_addr, str(e)))
            break

        if delay is not None:
            delay *= 1000
            logger.info("%s get ping in %0.4fms" % (dest_addr, delay))
