using System.Data.Common;

namespace PgClient.PgNet;

/// <see cref="DbProviderFactory"/> for the PgClient driver. Register with
/// <see cref="DbProviderFactories.RegisterFactory(string, DbProviderFactory)"/>
/// or use directly.
public sealed class PgDbProviderFactory : DbProviderFactory
{
    public static readonly PgDbProviderFactory Instance = new();

    private PgDbProviderFactory() { }

    public override DbConnection CreateConnection() => new PgDbConnection();
    public override DbCommand CreateCommand() => new PgDbCommand();
    public override DbParameter CreateParameter() => new PgDbParameter();
    public override DbConnectionStringBuilder CreateConnectionStringBuilder() => new DbConnectionStringBuilder();
}
