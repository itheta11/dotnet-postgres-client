message structure for row description 'T'

Structure (RowDescription)
Field	Type	Size (bytes)	Description
Message type	byte	1	'T' (0x54)
Length	int32	4	Total message length, including this field
Field count	int16	2	Number of columns described
For each field:			
→ Field name	cstring	variable	Null-terminated string
→ Table OID	int32	4	OID of the table this column belongs to (0 if not a table column)
→ Column attribute number	int16	2	Attribute number of the column (0 if not applicable)
→ Data type OID	int32	4	OID of the data type (e.g., 23 = int4, 25 = text)
→ Data type size	int16	2	Size in bytes (e.g., -1 = variable-width types like text)
→ Type modifier	int32	4	Type modifier (usually -1 if not applicable)
→ Format code	int16	2	0 = text, 1 = binary