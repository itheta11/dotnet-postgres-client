Step-by-Step Flow of the Startup Phase
1. TCP Connection
The client opens a TCP connection to the PostgreSQL server.
Default port: 5432
Once connected, the client must immediately send a Startup Message (no SSL/TLS yet).
2. SSL Negotiation (optional)
Before the main startup message, the client may ask if the server supports SSL/TLS.
SSL Request Message
Field	Type	Length	Description
Length	Int32	4 bytes	Total message length including self (8)
SSL Request Code	Int32	4 bytes	Fixed value 80877103 (0x04D2162F)
Client sends this 8-byte message right after TCP connect.
Server’s Response
Response	Meaning
'S'	Server accepts SSL — client upgrades the connection to TLS
'N'	Server rejects SSL — client continues in plaintext
(No response)	Connection closed — client cannot proceed
If SSL is accepted, all future communication happens over TLS.
3. Startup Message
After SSL negotiation (or immediately if not using SSL), the client sends the StartupMessage.
Structure of Startup Message
Field	Type	Description
Length	Int32	Total length in bytes including this field
Protocol version	Int32	e.g., 196608 = 3.0 (major=3, minor=0)
Parameters	String pairs	A sequence of key-value pairs
Terminator	Byte	A zero byte 0x00 marking the end
Each parameter is sent as two null-terminated strings:
key\0value\0...key\0value\0\0
Common Parameters
Key	Example Value	Description
user	postgres	Database username
database	testdb	Database name
application_name	psql	Optional
client_encoding	UTF8	Optional
options	-c statement_timeout=0	Optional
✅ Example (in bytes):
00 00 00 3F    # Length = 63 bytes
00 03 00 00    # Protocol version 3.0
75 73 65 72 00 70 6F 73 74 67 72 65 73 00 # user=postgres
64 61 74 61 62 61 73 65 00 74 65 73 74 64 62 00 # database=testdb
00
4. Server Response: Authentication Negotiation
The server now responds with one of several Authentication messages.
Message Type	Byte	Description
R	0x52	Authentication request
E	0x45	Error response
S	0x53	Parameter status
K	0x4B	Backend key data
Z	0x5A	Ready for query
Authentication Request (R)
Field	Type	Description
Length	Int32	Total message length
Auth Type	Int32	Authentication method
Payload	Depends	Method-dependent data
Auth Types:
Code	Method	Description
0	Ok	Authentication successful
2	KerberosV5	(rare)
3	CleartextPassword	Plain password required
5	MD5Password	MD5 hash of password
10	SASL	Used for SCRAM-SHA-256 (modern)
5. Client Authentication Response
Based on the authentication type:
For MD5: client sends password_message with hash.
For SCRAM: client sends multiple messages (SCRAM Initial, Continue, Final).
6. ParameterStatus, BackendKeyData, ReadyForQuery
Once authenticated:
Server sends S (ParameterStatus) for parameters like server_version, client_encoding, etc.
Then K (BackendKeyData) with process ID and secret key.
Finally Z (ReadyForQuery), signaling connection is ready for SQL commands.
🧩 Summary Diagram
Client                          Server
  | -------- TCP CONNECT --------> |
  |                                |
  | ---- SSLRequest (optional) --> |
  | <--- 'S' or 'N' -------------- |
  |                                |
  | ---- StartupMessage ----------> |
  | <--- AuthenticationRequest ---- |
  | ---- Password/SASL Response --> |
  | <--- AuthenticationOk --------- |
  | <--- ParameterStatus ---------- |
  | <--- BackendKeyData ----------- |
  | <--- ReadyForQuery ------------ |
  |                                |
Connection Ready
🧠 In Short
The Startup Phase is composed of:
TCP connection
Optional SSL negotiation
Startup message (parameters + protocol version)
Authentication exchange
Server setup messages
Ready-for-query message
After this, the PostgreSQL frontend/backend protocol switches to query execution mode.
Would you like me to show the exact binary layout (with byte offsets and examples) of the Startup Message and Authentication Request messages next? It’ll help if you’re writing a TCP client from scratch.