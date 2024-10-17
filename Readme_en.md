#XWT
XWT is a Web Token library implemented based on golang-jwt. It not only implements the standard JWT (JSON Web Token) format but also extends support for Protobuf Web Token (PWT).

##Composition
The XWT token consists of three parts: Header, Payload, and Signature, each separated by a period (".").

###Header
It specifies the type of Payload and the signing algorithm used. The Header is serialized with JSON and then Base64 encoded.

For example, a Header that specifies the ES256 algorithm and PWT type, in its original form, is:

```
{"alg":"ES256","typ":"PWT"}
```

And in its encoded form, it is:
```
eyJhbGciOiJFUzI1NiIsInR5cCI6IlBXVCJ9
```

###Payload
It contains the valid information of the token, and its serialization format is determined by the typ field in the Header, which can be either JSON or Protocol Buffers format.

###Signature
The signature is created using the algorithm specified in the Header and a private key, applied to the serialized and encoded Header and Payload to ensure the integrity of the Payload and prevent tampering.

##PWT
PWT (Protobuf Web Token) uses Protocol Buffers, an efficient data serialization framework, to encode the token payload (Payload) format.

###Advantages
1）PWT uses compact Protocol Buffers for serialization, making the Payload smaller than JWT, thus occupying less bandwidth for network transmission;
2）The Payload of PWT is encoded with Protocol Buffers, offering better data security compared to the plaintext Payload of JWT.

##Claims
Claims in XWT is an interface that serves as the fundamental unit for XWT to serialize and deserialize Payload;

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
