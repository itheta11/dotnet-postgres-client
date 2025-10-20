Overview of Post-Authentication Flow
After successful authentication, the PostgreSQL server transitions to the ready-for-query state.
You’ll now exchange Frontend → Backend and Backend → Frontend messages.
Here’s the sequence:
Backend → Client
R — AuthenticationOk (you already handled)
S — ParameterStatus
K — BackendKeyData
Z — ReadyForQuery
Frontend → Backend
Q — Query message
Backend → Client (varies based on query)
T — RowDescription
D — DataRow
C — CommandComplete
Z — ReadyForQuery
🔤 Backend Message Codes to Handle After Authentication
Code	Name	Description
S	ParameterStatus	Key/value pairs of runtime parameters like client_encoding, DateStyle, etc. Sent after auth.
K	BackendKeyData	Process ID + secret key for cancel requests.
Z	ReadyForQuery	Indicates backend is ready for next query. You must wait for this before sending another query.
T	RowDescription	Describes columns of a result set (column name, type OID, format code, etc.)
D	DataRow	Contains one row of data (binary or text format).
C	CommandComplete	Acknowledges completion of a query (e.g., SELECT 5, INSERT 0 1).
E	ErrorResponse	Error message from backend.
N	NoticeResponse	Warnings/info messages.
A	NotificationResponse	For LISTEN/NOTIFY notifications.
1	ParseComplete	Acknowledges a parsed statement (used in extended query flow).
2	BindComplete	Acknowledges bind step.
3	CloseComplete	Acknowledges close statement.
D	DataRow	One result row (you’ll get many of these).
For a simple query flow (using Q), you only need:
S, K, Z, T, D, C, E, N.
🧠 Understanding the “Query” Message
After you get the first ReadyForQuery (Z), you can send your first SQL command.
Frontend → Backend
Message Code: Q
Structure:
Byte1('Q') | Int32(length including self) | QueryString (null-terminated)
Example in bytes (ASCII "SELECT 1;"):
51 00 00 00 0D 53 45 4C 45 43 54 20 31 3B 00
51 = 'Q'
00 00 00 0D = length 13 bytes
53 45 4C 45 43 54 20 31 3B 00 = "SELECT 1;" + null terminator
🧩 Example Query Sequence
1️⃣ Send “SELECT 1;”
Client → Server: Q (SELECT 1;)
2️⃣ Receive messages in sequence:
T — RowDescription
D — DataRow
C — CommandComplete
Z — ReadyForQuery
Example (in plain form)
Message	Description
T	RowDescription → column count (1), column name (“?column?”), type OID (23 = int4), etc.
D	DataRow → column count (1), value (“1”).
C	CommandComplete → “SELECT 1”.
Z	ReadyForQuery → ready for next command.
⚙️ Pseudo-code Flow Example (C#-style)
await SendQueryAsync("SELECT 1;");

while (true)
{
    byte messageType = await ReadByteAsync();
    int length = await ReadInt32Async();

    switch (messageType)
    {
        case (byte)'T': // RowDescription
            ParseRowDescription(await ReadBytesAsync(length - 4));
            break;

        case (byte)'D': // DataRow
            ParseDataRow(await ReadBytesAsync(length - 4));
            break;

        case (byte)'C': // CommandComplete
            ParseCommandComplete(await ReadBytesAsync(length - 4));
            break;

        case (byte)'Z': // ReadyForQuery
            return; // done
    }
}
🧱 Extended Query Protocol (Optional, Later)
Once you handle simple Q messages, you can implement the extended query protocol for prepared statements:
Code	Meaning
P	Parse
B	Bind
D	Describe
E	Execute
S	Sync
H	Flush
But this is optional — most clients start with the simple query protocol.
✅ Next Steps for You
Now that authentication is working:
Handle ParameterStatus, BackendKeyData, and wait for ReadyForQuery.
Implement sending and receiving of Q (simple query) messages.
Parse responses:
T → build a list of column metadata.
D → read field values as strings (or binary).
C → note command completion.
Send next queries once you see Z (ReadyForQuery).
Would you like me to show detailed byte parsing examples for RowDescription and DataRow messages next?
That’s the most critical step to execute real queries like SELECT id, name FROM users;.