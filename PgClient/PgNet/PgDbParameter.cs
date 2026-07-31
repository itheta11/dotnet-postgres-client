using System.Data;
using System.Data.Common;

namespace PgClient.PgNet;

/// A single named/positional parameter for <see cref="PgDbCommand"/>.
///
/// Only <see cref="Value"/> is required — the underlying driver infers the
/// Postgres OID from the CLR type when <see cref="DbType"/> is left unset.
public sealed class PgDbParameter : DbParameter
{
    private string _parameterName = string.Empty;
    private object? _value;

    public override DbType DbType { get; set; } = DbType.Object;
    public override ParameterDirection Direction { get; set; } = ParameterDirection.Input;
    public override bool IsNullable { get; set; }
    [System.Diagnostics.CodeAnalysis.AllowNull]
    public override string ParameterName
    {
        get => _parameterName;
        set => _parameterName = value ?? string.Empty;
    }
    [System.Diagnostics.CodeAnalysis.AllowNull]
    public override string SourceColumn { get; set; } = string.Empty;
    public override object? Value
    {
        get => _value;
        set => _value = value;
    }
    public override bool SourceColumnNullMapping { get; set; }
    public override int Size { get; set; }

    public PgDbParameter() { }
    public PgDbParameter(string name, object? value) { ParameterName = name; Value = value; }

    public override void ResetDbType() => DbType = DbType.Object;

    internal Query.PgParameter ToPgParameter()
    {
        uint oid = Types.PgTypeOidFromDbType(DbType);
        return new Query.PgParameter(Value, oid);
    }
}
