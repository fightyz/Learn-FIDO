####UAFMessage
dictionary UAFMessage {  
    required DOMString **uafProtocolMessage**;  
    Object               **additionalData**;  
};

uafProtocolMessage才是UAF的报文,additionalData是Client的实现方自己的一些数据。

####Android Intent API
#####org.fidoalliance.uaf.permissions.FIDO_CLIENT
在Android 5之前，这个intent必须申明。

#####org.fidoalliance.uaf.permissions.ACT_AS_WEB_BROWSER
似乎是User Agent要使用origin parameter时，需要申明这个。

#####channelBindings

#####UAFIntentType enumeration
注意里面有个DISCOVER的Intent。这个是用于发现可用的认证器的，其对应ASM中的

####org.fidoalliance.intent.FIDO_OPERATION Intent
所有的ASM同FIDO Client交互都是用的这个Intent.当FIDO UAF Client与ASM进行交互时，FIDO Client必须向这个Client添加一个extra，就是ASMRequest。
