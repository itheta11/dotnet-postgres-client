Protocol Phases Overview
1.Startup Phase
Before authentication — untagged messages.
2.Authentication Phase
Server challenges the client.
3.Query Phase
Normal exchange of queries and results.
4.Termination Phase


Message strucuture
Startup message (sent by client) has no initial type byte:

| Length (4 bytes) | Protocol version (4 bytes) | Parameters... |

--------------------------------------------

Each message after startup:

| Type (1 byte) | Length (4 bytes, int32) | Payload (n bytes) |




CLIENT → SERVER Messages (Frontend Codes)
Code	Message Name	Description
—	StartupMessage	Sent first (no type byte). Contains protocol version and parameters like user, database.
p	PasswordMessage	Contains password in cleartext, MD5, or SASL format.
Q	Query	Simple query string (terminated by \0).
P	Parse	Parse a prepared statement.
B	Bind	Bind values to a prepared statement.
E	Execute	Execute a prepared or portal statement.
S	Sync	Marks the end of a series of extended query commands.
D	Describe	Ask for description of a prepared statement or portal.
H	Flush	Forces server to send pending output.
X	Terminate	Close the connection.
F	FunctionCall	Call a function (legacy).
c	CopyDone	Client done sending COPY data.
d	CopyData	Send data during COPY.
f	CopyFail	Indicate COPY error.
G	CopyInResponse	Client sends COPY data to server.
H	Flush	Ask to flush buffered messages.
R	(not used by client)	Reserved for server.
🔹 SERVER → CLIENT Messages (Backend Codes)
Code	Message Name	Description
R	Authentication	Server asks for authentication (various methods).
K	BackendKeyData	Contains backend PID and secret key (for cancel).
S	ParameterStatus	Server informs of runtime parameters.
Z	ReadyForQuery	Indicates the server is ready for next query.
T	RowDescription	Describes result set columns.
D	DataRow	Actual result row data.
C	CommandComplete	Indicates completion of a command (like SELECT 1).
E	ErrorResponse	Error information.
N	NoticeResponse	Non-fatal notice/warning.
A	NotificationResponse	NOTIFY message from LISTEN.
V	FunctionCallResponse	Function call result (legacy).
1	ParseComplete	Confirms prepared statement parse.
2	BindComplete	Confirms bind successful.
3	CloseComplete	Confirms close successful.
I	EmptyQueryResponse	Indicates empty query string.
t	ParameterDescription	Describes input parameters of prepared statement.
n	NoData	Indicates prepared statement returns no rows.
G	CopyInResponse	Server expects client to send COPY data.
H	CopyOutResponse	Server will send COPY data to client.
W	CopyBothResponse	COPY in both directions (used in logical replication).
d	CopyData	COPY data packet.
c	CopyDone	COPY complete.
s	PortalSuspended	Indicates portal execution suspended (fetch/limit).
0	(unused)	Reserved.
🔹 AUTHENTICATION TYPES (R message subcodes)
When server sends R (Authentication), the next 4 bytes are an int32 auth code:
Code	Type	Meaning
0	AuthenticationOk	Authentication successful
2	AuthenticationKerberosV5	Kerberos V5 required
3	AuthenticationCleartextPassword	Send cleartext password
5	AuthenticationMD5Password	MD5 password expected
7	AuthenticationGSS	Start GSS authentication
8	AuthenticationGSSContinue	Continue GSS
9	AuthenticationSSPI	SSPI authentication
10	AuthenticationSASL	SASL (SCRAM, etc.)
11	AuthenticationSASLContinue	Continue SASL
12	AuthenticationSASLFinal	Final SASL message
