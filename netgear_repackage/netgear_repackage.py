#!/usr/bin/python3
import os,sys
import struct
import zlib

# binwalk -Me R6400v2-V1.0.4.120_10.0.91.chk 

# DECIMAL       HEXADECIMAL     DESCRIPTION
# --------------------------------------------------------------------------------
# 58            0x3A            TRX firmware header, little endian, image size: 47222784 bytes, CRC32: 0xB9C3C9B8, flags: 0x0, version: 1, header size: 28 bytes, loader offset: 0x1C, linux kernel offset: 0x20BD98, rootfs offset: 0x0
# 86            0x56            LZMA compressed data, properties: 0x5D, dictionary size: 65536 bytes, uncompressed size: 5276608 bytes
# 2145746       0x20BDD2        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 45075386 bytes, 1798 inodes, blocksize: 131072 bytes, created: 2021-09-03 09:27:39


def mk_firmware(orig_firm, orig_hsquStart):
    if not orig_firm or not orig_hsquStart:
        print ("check your args.")
    cmd="mksquashfs squashfs-root squashfs-root.squash -comp xz"
    os.system(cmd)
    with open("squashfs-root.squash","rb") as fhsqs:
        _content=fhsqs.read()
        fileSize=len(_content)

    with open(orig_firm,"rb") as forig:
        orig_content=forig.read()
        # orig_header = TRX header + kernel
        orig_header=orig_content[0x3a:orig_hsquStart]

    with open("out.chk","wb") as fout:
        fout.write(orig_header)
        fout.write(_content)
        out_size=fileSize+(orig_hsquStart-0x3a)
        if (out_size % 0x1000) != 0:
            pad_size=0x1000-(out_size%0x1000)
            out_size=out_size+0x1000-(out_size%0x1000)
            if pad_size > 0:
                for i in range(0,pad_size):
                    fout.write(struct.pack("b",0x0))
            
    # print ("real outSize:", out_size)
    return out_size

# crc, filesize
def patch_firmware(out_size):
    with open("out.chk", "rb") as fout_r:
        content = fout_r.read()
        # print ("len content:", len(content))
    
    data = content[12:12+out_size] 
    crc = (~zlib.crc32(data)) & 0xffffffff

    with open("last.chk", "wb") as fout_w:
        fout_w.write(content[:0x4])
        fout_w.write(struct.pack("I", out_size))
        fout_w.write(struct.pack("I", crc))
        fout_w.write(content[0xc:])
    
    cmd = "touch rootfs && \
        ./packet -k ./last.chk -f rootfs -b compatible_r6400.txt \
        -ok kernel_image -oall kernel_rootfs_image -or rootfs_image \
        -i ambitCfg.h && \
        rm -f rootfs && cp kernel_rootfs_image.chk R6400v2_`date +%m%d%H%M`.chk"    
    os.system(cmd)


def open_telnet():
    cmd="mv squashfs-root/usr/sbin/dlnad squashfs-root/usr/sbin/dlnadd;touch squashfs-root/usr/sbin/dlnad; \
        echo '#!/bin/sh \
        \n/bin/utelnetd -p 12580 & \
        \n/usr/sbin/dlnadd &' \
        > squashfs-root/usr/sbin/dlnad; chmod 755 squashfs-root/usr/sbin/dlnad"
    os.system(cmd)

def cleann():
    cmd="rm -f rootfs_image.chk; rm -f kernel*;rm -f out.chk;rm -f squashfs-root.squash;rm -f last.chk"
    os.system(cmd)


if __name__ == '__main__':
    # open_telnet()
    _size=mk_firmware("R6400v2-V1.0.4.120_10.0.91.chk",0x20BDD2)
    patch_firmware(_size)
    cleann()
