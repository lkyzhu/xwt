#XWT
XWT是一个基于golang-jwt实现的令牌库，它不仅实现了标准的JWT（JSON Web Token）格式，还扩展了对Protobuf Web Token（PWT）的支持。

##组成
XWT的令牌由三部分组成：头部（Header）、负载（Payload）和签名（Signature），各部分通过"."分隔。
###头部（Header）
指明Payload的类型和使用的签名算法，Header使用JSON序列化后进行Base64编码。

例如，一个指定了ES256算法和PWT类型的Header，其原始形式为：
```
{"alg":"ES256","typ":"PWT"}
```
编码后的形式为：
```
eyJhbGciOiJFUzI1NiIsInR5cCI6IlBXVCJ9
```


###负载（Payload）
包含令牌的有效信息，其序列化格式由Header中的typ字段决定，可以是JSON或Protocol Buffers格式。

###签名（Signature）
使用Header中指定的算法和私钥，对经过序列化和编码的Header和Payload进行签名，以确保Payload的完整性并防止篡改。

##PWT
PWT（Protobuf Web Token）采用Protocol Buffers（一种高效的数据序列化框架）来编码令牌负载（Payload）的令牌格式。
###优势
1）PWT的使用紧凑的Protocol Buffers进行序列化，Payload相对JWT更小，网络传输占用带宽更小；
2）PWT的Payload是经过Protocol Buffers编码的，相对JWT明文的Payload，数据安全性更有优势；

##Claims
Claims在XWT中是一个interface，是XWT序列化和反序列化Payload基本单元；
```
type Claims interface {
    GetExpirationTime() int64
    GetIssuedAt() int64
    GetNotBefore() int64
    GetIssuer() string
    GetSubject() string
    GetAudience() []string
    Type() string
    Marshal() ([]byte, error)
    Unmarshal([]byte) error
}

```
