
#问题和建议
##使用github.com/gogo/protobuf/proto对protobuf的Message库序列化和反序列化时，存在循环递归问题
问题原因：
1）该protobuf库，在序列化时，会检查Message是否实现了Mashal/Unmarshal接口，如果实现了Marshaler interface, 如果实现了，就直接调用Message的Mashal/Unmarshal函数（此处导致循环递归调用问题）
Marshaler/Unmarshal interface定义：
``` 
// Marshaler is the interface representing objects that can marshal themselves.                                                                          
type Marshaler interface {
    Marshal() ([]byte, error)                                                                                                                            
}        

type Unmarshaler interface {                                                                                                                             
    Unmarshal([]byte) error
}     
```

接口序列化定义：
```
// Marshal takes a protocol buffer message
// and encodes it into the wire format, returning the data.
// This is the main entry point.
func Marshal(pb Message) ([]byte, error) {
    if m, ok := pb.(newMarshaler); ok {
        siz := m.XXX_Size()
        b := make([]byte, 0, siz)
        return m.XXX_Marshal(b, false)
    }
    if m, ok := pb.(Marshaler); ok {
        // If the message can marshal itself, let it do it, for compatibility.
        // NOTE: This is not efficient.
        return m.Marshal()
    }
    // in case somehow we didn't generate the wrapper
    if pb == nil {
        return nil, ErrNil
    }
    var info InternalMessageInfo
    siz := info.Size(pb)
    b := make([]byte, 0, siz)
    return info.Marshal(b, pb, false)
}   

func Unmarshal(buf []byte, pb Message) error {                                                                                                           
    pb.Reset()                                                                                                                                           
    if u, ok := pb.(newUnmarshaler); ok {                                                                                                                
        return u.XXX_Unmarshal(buf)                                                                                                                      
    }                                                                                                                                                    
    if u, ok := pb.(Unmarshaler); ok {                                                                                                                   
        return u.Unmarshal(buf)                                                                                                                          
    }                                                                                                                                                    
    return NewBuffer(buf).Unmarshal(pb)                                                                                                                  
}                                     
```

解决办法：
1）使用官方库：google.golang.org/protobuf/proto（推荐）
2）将protobuf结构体封装成一个新的类型（如：xxxMessage），实现Marshal/Unmarshal函数
