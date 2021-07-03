
console.log("hello ~ zoom with version 561_172")
let DEBUG = 0
var base = Module.findBaseAddress("Zoom");
console.log("offSet is:", base)

//ssl_session_get_id 和ssl_get_session 通过特征找起来比较麻烦, 由于这俩函数逻辑比较简单，就自己实现
function ssl_session_get_id_func(ssl, len) {
    if (len) {
        var lenn = Memory.readU64(ptr(ssl.add(0x150)))
        Memory.writeU32(len, lenn)
    }
    return ptr(ssl.add(0x158))
}

function ssl_get_session_func(ssl) {
    return Memory.readU64(ssl.add(0x510))
}

function getSslSessionId(ssl) {
    var session = ssl_get_session_func(ssl);
    if (session == 0) {
        return 0;
    }
    var len = Memory.alloc(4);
    var p = ssl_session_get_id_func(session, len);
    len = Memory.readU32(len);
    var session_id = "";
    for (var i = 0; i < len; i++) {
        session_id += ("0" + Memory.readU8(p.add(i)).toString(16).toUpperCase()).substr(-2);
    }
    return session_id;
}

function arraybuffer2hexstr(buffer) {
    var hexArr = Array.prototype.map.call(
        new Uint8Array(buffer),
        function (bit) {
            return ('00' + bit.toString(16)).slice(-2)
        }
    )
    return hexArr.join('');
}

//0x01  get client_random, master_secret
var client
var master
// 0xB945B8
// 先通过0xB61518  tls1_PRF 确定版本相关信息，再直接hook 获取master scret
Interceptor.attach(base.add(0xB6176C), {
    onEnter: function (args) {
        //console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
        var oob = Memory.readU64(args[0].add(0xa8))
        client = oob.add(0xb8)
        // console.log(client)
        master = args[1]
    },
    onLeave: function (retval) {
        console.log("CLIENT_RANDOM", arraybuffer2hexstr(Memory.readByteArray(ptr(client), 32)), arraybuffer2hexstr(Memory.readByteArray(ptr(master), 48)))
    }
})

//0x02 bypass 证书校验
//0x100B39B4C --  ssl_verify_cert_chain 
Interceptor.attach(base.add(0xB39B4C), {
    onEnter: function (args) {
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
        console.log('call ssl_verify_cert_chain')
    },
    onLeave: function (retval) {
        console.log("ret:", retval)
        retval.replace(1)
    }
})

//0x04  CmmCStr
CmmCStr:
// --------------------------------------------------
// |00|01|02|03|04|05|06|07|08|09|0a|0b|0c|0d|0e|0f|
// --------------------------------------------------
//     address                | str or ptr2str
//                       len  |                 |flag


//encDataArry
// --------------------------------------------------
// |00|01|02|03|04|05|06|07|08|09|0a|0b|0c|0d|0e|0f|
// --------------------------------------------------
// |     data              |   data_Len            |
// |     outdata           |   outdata_Len         |


// 1014579A0 alloc func, add func(101457CD8)
// alloc memory ret:0x10981ca00
//                  + 0xb8 --> ptr, +8 real pointer
//                  + 0xc0 

// aslr 0x0000000002bf8000
// frame #3: 0x0000000104048b50 Zoom`___lldb_unnamed_symbol93272$$Zoom + 1428
// frame #4: 0x000000010404abe8 Zoom`___lldb_unnamed_symbol93293$$Zoom + 1864
// frame #5: 0x000000010404faec Zoom`___lldb_unnamed_symbol93317$$Zoom + 564
// frame #6: 0x0000000103fe62b0 Zoom`___lldb_unnamed_symbol91997$$Zoom + 148
// frame #7: 0x00000001043b3dd4 Zoom`___lldb_unnamed_symbol108553$$Zoom + 852
// frame #8: 0x0000000102d85298 Zoom`___lldb_unnamed_symbol8447$$Zoom + 160
// frame #9: 0x00000001034ef39c Zoom`___lldb_unnamed_symbol45731$$Zoom + 656

var pptr
var targetStr
if (DEBUG) {
    Interceptor.attach(base.add(0xc43c), {
        onEnter: function (args) {
            pptr = args[0]
            targetStr = args[1]
            //console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
            var target = Memory.readUtf8String(targetStr)
            if (target != "AutoAccept" && target && target != ".") {
                console.log('[INFO]', Memory.readPointer(pptr), target)
            }
            if (target == "hash_macaddress" || target == "password" || target == "cid" || target == "ecp" || target == "email") {
                console.log("Header:", target, ":\r\n", Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
            }
        },
    })

    // 0x1010f6434 EVPEncode_base64
    Interceptor.attach(base.add(0x10f6434), {
        onEnter: function (context) {
            if (this.context.x1) {
                var nLen = Memory.readU32(this.context.x0.add(8))
                var pptr = Memory.readPointer(this.context.x0)
                // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
                var base64ddd = Memory.readUtf8String(pptr, nLen)
                console.log('\r\n---call 0x10f6434 base64:', base64ddd, '\r\n')
                // if (base64ddd == "SxcWOcAmEfwsXXM6EFESsFkxG9wNjsuZXbjDLIyksKg=") {
                //     console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
                // }
            }
        }
    })
}

//0x03 log infoLog对应信息
if (ObjC.available) {
    try {
        // -[UIDevice generateDeviceIdentifier:]
        var className = "UIDevice";
        var funcName = "- generateDeviceIdentifier:";
        var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
        Interceptor.attach(hook.implementation, {
            onEnter: function (args) {
                var NSString1 = new ObjC.Object(args[2]);
                var strr = NSString1.UTF8String();
                console.log("genege arg:", strr)
            },
            onLeave: function (retval) {
                var NSString = new ObjC.Object(retval);
                var str = NSString.UTF8String();
                console.log("genege ret:", str)
            }
        });
    }
    catch (err) {
        console.log("[!] Exception2: " + err.message);
    }


    try {
        var className = "ZPLogHelper";
        var funcName = "+ infoLog:";
        var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
        Interceptor.attach(hook.implementation, {
            onEnter: function (args) {
                var NSString = new ObjC.Object(args[2]);
                var str = NSString.UTF8String();
                console.log("+[ZPLogHelper infoLog:]", str)
            }
        });
    }
    catch (err) {
        console.log("[!] Exception2: " + err.message);
    }

    try {
        var className = "ZPLogHelper";
        var funcName = "+ infoLog:withString:";
        var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
        Interceptor.attach(hook.implementation, {
            onEnter: function (args) {
                var str_1 = new ObjC.Object(args[2]).UTF8String();
                var str_2 = new ObjC.Object(args[3]).UTF8String();
                console.log("+[ZPLogHelper infoLog:withString]", str_1, str_2)
            }
        });
    }
    catch (err) {
        console.log("[!] Exception2: " + err.message);
    }
}

// 0x05 SSL_read 0xB40E38 
Interceptor.attach(base.add(0xB40E38), {
    onEnter: function (args) {
        this.message = "SSL_read"
        this.buf = args[1]
        console.log('call 0xB40E38 ssl_read', args[2])
        console.log(" -> ssl_session_id is:", getSslSessionId(args[0]))
        // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');

    },
    onLeave: function (retval) {
        console.log("SSL_read ret:", retval)
        var byteArray = Memory.readByteArray(this.buf, parseInt(retval))
        console.log(byteArray, '\n')
    }
})

// 0x06 SSL_write 0xB40FEC
Interceptor.attach(base.add(0xB40FEC), {
    onEnter: function (args) {
        //bad command
        console.log('call 0xB40FEC ssl_write', args[0], args[2])
        console.log(" ->ssl_session_id is:", getSslSessionId(args[0]))
        // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
        var byteArray = Memory.readByteArray(args[1], parseInt(args[2]))
        console.log(byteArray)
    },
    onLeave: function (retval) {
        console.log("SSL_Write ret:", retval, '\n')
    }
})



function get_aes_key_iv(a3, a4) {
    var v8, v10, v12, v16, v18, v20, v22, key, iv
    // key:
    v16 = Memory.readU8(a3.add(31))
    v10 = String.fromCharCode(v16)
    if (v16 & 0x80 != 0) {
        v16 = Memory.readU64(a3.add(16))
    }
    if (v10 >= 0) {//'0'--> 48
        console.log("222", v10)
        v18 = a3.add(8)
    } else {
        v18 = Memory.readU64(a3.add(8))
    }
    if (v16) {
        key = v18
    } else {
        key = 0
    }
    // iv:
    v8 = a4
    v20 = Memory.readU8(v8.add(31))
    v12 = String.fromCharCode(v20)
    if (v20 & 0x80 != 0) {
        v20 = Memory.readU64(v8.add(16))
    }
    if (v12 >= 0) {
        console.log("111", v12)
        v22 = v8.add(8)
    } else {
        v22 = Memory.readU64(v8.add(8))
    }
    if (v20) {
        iv = v22
    } else {
        iv = 0
    }
    if (iv && key) {
        // console.log("key:", key, "iv", iv)
        // console.log(hexdump(ptr(key)), hexdump(ptr(iv)))
        console.log("key", arraybuffer2hexstr(Memory.readByteArray(ptr(key), 32)), "iv", arraybuffer2hexstr(Memory.readByteArray(ptr(iv), 32)))
    }
}

var _encrypted
// 0x00000001010f9298 evp_crypter_aes_128cbc
Interceptor.attach(base.add(0x10f9298), {
    onEnter: function (args) {
        console.log('[EVP_AES_128_CBC] call 0x10f9298 evp_crypter_aes_128cbc ================func\n')
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');

        _encrypted = args[4]
        get_aes_key_iv(args[2], args[3])
    },
    onLeave: function (retval) {
        var _ptr = Memory.readU64(_encrypted.add(8))
        var _len = Memory.readU32(_encrypted.add(16))
        console.log("aes_128_cbc ret:", _len)
        var byteArray = Memory.readByteArray(ptr(_ptr), _len)
        console.log("encrypted data:", arraybuffer2hexstr(byteArray), '\n')
        console.log("==================end")

    }
})
