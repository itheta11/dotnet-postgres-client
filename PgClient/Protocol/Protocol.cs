using System;

namespace PgClient.Protocol
{
    /// <summary>
    /// Protocol constants, enums, and identifiers for PostgreSQL TCP client communication.
    /// Covers frontend (client → server), backend (server → client),
    /// authentication, and startup phases.
    /// </summary>
    public static class PostgresProtocol
    {
        // ------------------------------------------------------------------------
        // PostgreSQL Protocol Version (currently 3.0)
        // ------------------------------------------------------------------------
        public const int ProtocolVersion = 3; // 196608 decimal

        // ------------------------------------------------------------------------
        // Special Startup Request Codes (no message type byte)
        // ------------------------------------------------------------------------
        public static class StartupCodes
        {
            public const int SSLRequest = 80877103;      // Request SSL negotiation
            public const int CancelRequest = 80877102;   // Request query cancel
            public const int GSSENCRequest = 80877104;   // Request GSS encryption
        }

        // ------------------------------------------------------------------------
        // Frontend → Backend (Client → Server) message codes
        // ------------------------------------------------------------------------
        public enum FrontendMessageCode : byte
        {
            // Basic query flow
            Query = (byte)'Q',             // Simple Query
            Parse = (byte)'P',             // Parse prepared statement
            Bind = (byte)'B',              // Bind parameters to prepared statement
            Execute = (byte)'E',           // Execute a prepared or portal statement
            Sync = (byte)'S',              // End of extended query messages
            Describe = (byte)'D',          // Describe a prepared statement or portal
            Close = (byte)'C',             // Close a prepared statement or portal
            Flush = (byte)'H',             // Flush pending output
            Terminate = (byte)'X',         // Terminate connection

            // Copy protocol (for bulk data)
            CopyData = (byte)'d',
            CopyDone = (byte)'c',
            CopyFail = (byte)'f',

            // Authentication
            PasswordMessage = (byte)'p',   // Send password data (MD5/SASL/plain)

            // Deprecated
            FunctionCall = (byte)'F'       // Legacy function call
        }

        // ------------------------------------------------------------------------
        // Backend → Frontend (Server → Client) message codes
        // ------------------------------------------------------------------------
        public enum BackendMessageCode : byte
        {
            // Authentication & session setup
            Authentication = (byte)'R',
            BackendKeyData = (byte)'K',
            ParameterStatus = (byte)'S',
            ReadyForQuery = (byte)'Z',  

            // Query results
            RowDescription = (byte)'T',
            DataRow = (byte)'D',
            CommandComplete = (byte)'C',
            EmptyQueryResponse = (byte)'I',
            NoData = (byte)'n',

            // Extended query responses
            ParseComplete = (byte)'1',
            BindComplete = (byte)'2',
            CloseComplete = (byte)'3',
            ParameterDescription = (byte)'t',
            PortalSuspended = (byte)'s',

            // Copy data
            CopyInResponse = (byte)'G',
            CopyOutResponse = (byte)'H',
            CopyBothResponse = (byte)'W',
            CopyData = (byte)'d',
            CopyDone = (byte)'c',

            // Notices and notifications
            ErrorResponse = (byte)'E',
            NoticeResponse = (byte)'N',
            NotificationResponse = (byte)'A',

            // Function call (legacy)
            FunctionCallResponse = (byte)'V'
        }

        // ------------------------------------------------------------------------
        // Authentication request codes (subtype of 'R' message)
        // ------------------------------------------------------------------------
        public enum AuthenticationCode : int
        {
            /// <summary>
            /// Authentication successful
            /// </summary>
            Ok = 0,

            /// <summary>
            /// Use Kerberos V5
            /// </summary>
            KerberosV5 = 2,
            CleartextPassword = 3,        // Expect cleartext password

            /// <summary>
            /// Expect MD5 password
            /// </summary>
            MD5Password = 5,

            /// <summary>
            /// Unix domain socket credential
            /// </summary>
            SCMCredential = 6,            // Unix domain socket credential
            GSS = 7,                      // Begin GSSAPI negotiation
            GSSContinue = 8,              // Continue GSS negotiation
            SSPI = 9,                     // Begin SSPI negotiation
            /// <summary>
            /// Begin SASL (SCRAM, etc.)
            /// </summary>
            SASL = 10,

            /// <summary>
            /// Continue SASL
            /// </summary>
            SASLContinue = 11,

            /// <summary>
            /// Final SASL exchange
            /// </summary>
            SASLFinal = 12
        }

        // ------------------------------------------------------------------------
        // ReadyForQuery transaction status indicators (in payload)
        // ------------------------------------------------------------------------
        public enum TransactionStatus : byte
        {
            Idle = (byte)'I',             // Not in transaction
            InTransaction = (byte)'T',    // Inside transaction block
            Error = (byte)'E'             // In failed transaction block
        }

        // ------------------------------------------------------------------------
        // Helper: Convert byte code to readable string (for debugging/logging)
        // ------------------------------------------------------------------------
        public static string DescribeFrontendCode(byte code)
        {
            return Enum.IsDefined(typeof(FrontendMessageCode), code)
                ? ((FrontendMessageCode)code).ToString()
                : $"Unknown(0x{code:X2})";
        }

        public static string DescribeBackendCode(byte code)
        {
            return Enum.IsDefined(typeof(BackendMessageCode), code)
                ? ((BackendMessageCode)code).ToString()
                : $"Unknown(0x{code:X2})";
        }
    }
}
    