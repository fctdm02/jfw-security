package com.compuware.frameworks.security.persistence.hibernate.dialect;

import java.sql.Types;

import org.hibernate.dialect.SQLServerDialect;

public class CompuwareSqlServerHibernateDialect extends SQLServerDialect {

    public CompuwareSqlServerHibernateDialect() {
        registerColumnType(Types.BIGINT, "bigint");
        registerColumnType(Types.BIT, "bit");
        registerColumnType(Types.CHAR, "nchar(1)");
        registerColumnType(Types.VARCHAR, 4000, "nvarchar($l)");
        registerColumnType(Types.VARCHAR, "nvarchar(max)");
        registerColumnType(Types.VARBINARY, 4000, "varbinary($1)");
        registerColumnType(Types.VARBINARY, "varbinary(max)");
        registerColumnType(Types.BLOB, "varbinary(max)");
        registerColumnType(Types.CLOB, "nvarchar(max)");
    }
}
