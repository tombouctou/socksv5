var inherits = require('util').inherits,
    EventEmitter = require('events').EventEmitter;

var CMD = require('./constants').CMD,
    ATYP = require('./constants').ATYP;

var STATE_VERSION            = 0,
    STATE_NMETHODS           = 1,
    STATE_METHODS            = 2,
    STATE_REQ_CMD            = 3,
    STATE_REQ_RSV            = 4,
    STATE_REQ_ATYP           = 5,
    STATE_REQ_DSTADDR        = 6,
    STATE_REQ_DSTADDR_VARLEN = 7,
    STATE_REQ_DSTPORT        = 8,

    STATE_V4_DSTPORT         = 10,
    STATE_V4_DSTIP           = 11,
    STATE_V4_USERID          = 12,
    STATE_V4A_DOMAIN         = 13;

function Parser(stream) {
  var self = this;

  this._stream = stream;
  this._listening = false;
  this.__onData = function(chunk) {
    self._onData(chunk);
  };

  this._state = STATE_VERSION;
  this._methods = undefined;
  this._methodsp = 0;
  this._cmd = 0;
  this._atyp = 0;
  this._dstaddr = undefined;
  this._dstaddrp = 0;
  this._dstport = undefined;
  this._username = undefined;

  this.authed = false;

  this.start();
}
inherits(Parser, EventEmitter);

Parser.prototype._onData = function(chunk) {
  var state = this._state,
      i = 0,
      len = chunk.length,
      left,
      chunkLeft,
      minLen,
      protoVer;

  while (i < len) {
    switch (state) {
      /*
        Socks V5:
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
  size  | 1  |    1     | 1 to 255 |
        +----+----------+----------+
        Socks V4:
        +----+----+----+----+----+----+----+----+----+----+....+----+
        | VN | CD | DSTPORT |       DSTIP       | USERID       |NULL|
        +----+----+----+----+----+----+----+----+----+----+....+----+
  size    1    1       2              4           variable       1
      */
      case STATE_VERSION:
        protoVer = chunk[i];
        if (protoVer !== 0x04 && protoVer !== 0x05) {
          this.emit('error',
                    new Error('Incompatible SOCKS protocol version: '
                              + chunk[i]));
          return;
        }
        ++i;
        if (this.authed || protoVer == 0x04)
          state = STATE_REQ_CMD;
        else
          state = STATE_NMETHODS;
      break;
      case STATE_NMETHODS:
        var nmethods = chunk[i];
        if (nmethods === 0) {
          this.emit('error', new Error('Unexpected empty methods list'));
          return;
        }
        ++i;
        ++state;
        this._methods = new Buffer(nmethods);
        this._methodsp = 0;
      break;
      case STATE_METHODS:
        left = this._methods.length - this._methodsp;
        chunkLeft = len - i;
        minLen = (left < chunkLeft ? left : chunkLeft);
        chunk.copy(this._methods,
                   this._methodsp,
                   i,
                   i + minLen);
        this._methodsp += minLen;
        i += minLen;
        if (this._methodsp === this._methods.length) {
          this.stop();
          this._state = STATE_VERSION;
          if (i < len)
            this._stream.unshift(chunk.slice(i));
          var methods = this._methods;
          this._methods = undefined;
          this.emit('methods', methods);
          return;
        }
      break;
      // =======================================================================
      /*
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

        Where:

              o  VER    protocol version: X'05'
              o  CMD
                 o  CONNECT X'01'
                 o  BIND X'02'
                 o  UDP ASSOCIATE X'03'
              o  RSV    RESERVED
              o  ATYP   address type of following address
                 o  IP V4 address: X'01'
                 o  DOMAINNAME: X'03'
                 o  IP V6 address: X'04'
              o  DST.ADDR       desired destination address
              o  DST.PORT desired destination port in network octet
                 order
      */
      case STATE_REQ_CMD:
        var cmd = chunk[i];
        if (cmd === CMD.CONNECT)
          this._cmd = 'connect';
        else if (cmd === CMD.BIND)
          this._cmd = 'bind';
        else if (cmd === CMD.UDP && protoVer == 0x05)
          this._cmd = 'udp';
        else {
          this.stop();
          this.emit('error', new Error('Invalid request command: ' + cmd));
          return;
        }
        ++i;
        if (protoVer == 0x05) {
          ++state;
        } else {
          state = STATE_V4_DSTPORT;
        }
      break;
      case STATE_V4_DSTPORT:
        this._dstport = chunk[i];
        ++i;
        this._dstport <<= 8;
        this._dstport += chunk[i];
        ++i;
        ++state;
      break;
      case STATE_V4_DSTIP:
        this._dstaddr = new Buffer(4);
        var addr = 0;
        for(var j = i; j < i + 4; ++j) {
          this._dstaddr[j - i] = chunk[j];
          addr <<= 8;
          addr += chunk[j];
        }
        i += 4;
        this._dstaddr = Array.prototype.join.call(this._dstaddr, '.');
        if (addr < 0x100) {
          this._atyp = ATYP.NAME;
        } else {
          this._atyp = ATYP.IPv4;
        }
        ++state;
      break;
      case STATE_V4_USERID:
        this._username = "";
        while(chunk[i] != 0) {
          this._username += String.fromCharCode(chunk[i])
          ++i;
        }
        ++i;
        if (this._atyp == ATYP.NAME) {
          state = STATE_V4A_DOMAIN;
        } else {
          this.stop();
          this.emit('request', {
            cmd: this._cmd,
            proto: protoVer,
            username: this._username,
            srcAddr: undefined,
            srcPort: undefined,
            dstAddr: this._dstaddr,
            dstPort: this._dstport
          });
          return;
        }
      break;
      case STATE_V4A_DOMAIN:
        this._dstaddr = "";
        while(chunk[i] != 0 && i < len) {
          this._dstaddr += String.fromCharCode(chunk[i])
          ++i;
        }
        ++i;
        this.stop();
        this.emit('request', {
          cmd: this._cmd,
          username: this._username,
          proto: protoVer,
          srcAddr: undefined,
          srcPort: undefined,
          dstAddr: this._dstaddr,
          dstPort: this._dstport
        });
        return;
      break;
      case STATE_REQ_RSV:
        ++i;
        ++state;
      break;
      case STATE_REQ_ATYP:
        var atyp = chunk[i];
        state = STATE_REQ_DSTADDR;
        if (atyp === ATYP.IPv4)
          this._dstaddr = new Buffer(4);
        else if (atyp === ATYP.IPv6)
          this._dstaddr = new Buffer(16);
        else if (atyp === ATYP.NAME)
          state = STATE_REQ_DSTADDR_VARLEN;
        else {
          this.stop();
          this.emit('error',
                    new Error('Invalid request address type: ' + atyp));
          return;
        }
        this._atyp = atyp;
        ++i;
      break;
      case STATE_REQ_DSTADDR:
        left = this._dstaddr.length - this._dstaddrp;
        chunkLeft = len - i;
        minLen = (left < chunkLeft ? left : chunkLeft);
        chunk.copy(this._dstaddr,
                   this._dstaddrp,
                   i,
                   i + minLen);
        this._dstaddrp += minLen;
        i += minLen;
        if (this._dstaddrp === this._dstaddr.length)
          state = STATE_REQ_DSTPORT;
      break;
      case STATE_REQ_DSTADDR_VARLEN:
        this._dstaddr = new Buffer(chunk[i]);
        state = STATE_REQ_DSTADDR;
        ++i;
      break;
      case STATE_REQ_DSTPORT:
        if (this._dstport === undefined)
          this._dstport = chunk[i];
        else {
          this._dstport <<= 8;
          this._dstport += chunk[i];
          ++i;

          this.stop();
          if (i < len)
            this._stream.unshift(chunk.slice(i));

          if (this._atyp === ATYP.IPv4)
            this._dstaddr = Array.prototype.join.call(this._dstaddr, '.');
          else if (this._atyp === ATYP.IPv6) {
            var ipv6str = '',
                addr = this._dstaddr;
            for (var b = 0; b < 16; ++b) {
              if (b % 2 === 0 && b > 0)
                ipv6str += ':';
              ipv6str += addr[b].toString(16);
            }
            this._dstaddr = ipv6str;
          } else
            this._dstaddr = this._dstaddr.toString();

          this.emit('request', {
            cmd: this._cmd,
            srcAddr: undefined,
            srcPort: undefined,
            dstAddr: this._dstaddr,
            dstPort: this._dstport
          });
          return;
        }
        ++i;
      break;
      // ===================================================================
    }
  }

  this._state = state;
};

Parser.prototype.start = function() {
  if (this._listening)
    return;
  this._listening = true;
  this._stream.on('data', this.__onData);
  this._stream.resume();
};

Parser.prototype.stop = function() {
  if (!this._listening)
    return;
  this._listening = false;
  this._stream.removeListener('data', this.__onData);
  this._stream.pause();
};

module.exports = Parser;
