import javascript
import semmle.javascript.security.dataflow.TaintTracking

/**
 * User input sources: req.query, req.body, req.params
 */
class UserInputSource extends TaintTracking::SourceNode {
  UserInputSource() {
    exists(Expr e |
      e = this.asExpr() and
      (
        e.toString() = "req.query" or
        e.toString() = "req.body" or
        e.toString() = "req.params"
      )
    )
  }
}

/**
 * SQL query sink: db.query/connection.query/execute(arg0)
 */
class SqlQuerySink extends TaintTracking::SinkNode {
  SqlQuerySink() {
    exists(FunctionCall call, Expr arg |
      arg = this.asExpr() and
      call.getArgument(0) = arg and
      (
        call.getCallee().getQualifiedName().matches("%db.query%") or
        call.getCallee().getQualifiedName().matches("%connection.query%") or
        call.getCallee().getQualifiedName().matches("%execute%")
      )
    )
  }
}

from TaintTracking::PathNode source1, TaintTracking::PathNode sink1
where
  source1 instanceof UserInputSource and
  sink1 instanceof SqlQuerySink and
  TaintTracking::localTaint(source1, sink1)
select sink1,
  "R001: User input flows into a SQL query. Possible injection."

/**
 * Template literal SQL sink
 */
class TemplateLiteralSqlSink extends TaintTracking::SinkNode {
  TemplateLiteralSqlSink() {
    exists(TemplateLiteral t, FunctionCall call |
      t = this.asExpr() and
      call.getArgument(0) = t and
      (
        call.getCallee().getQualifiedName().matches("%db.query%") or
        call.getCallee().getQualifiedName().matches("%connection.query%")
      )
    )
  }
}

from TaintTracking::PathNode source2, TaintTracking::PathNode sink2
where
  source2 instanceof UserInputSource and
  sink2 instanceof TemplateLiteralSqlSink and
  TaintTracking::localTaint(source2, sink2)
select sink2,
  "R002: User input flows into a template literal used as a SQL query."

/**
 * Command execution sink: child_process.exec/execSync/spawn
 */
class CommandSink extends TaintTracking::SinkNode {
  CommandSink() {
    exists(FunctionCall call, Expr cmdArg |
      cmdArg = this.asExpr() and
      call.getArgument(0) = cmdArg and
      call.getCallee().getQualifiedName().matches("child_process.%") and
      (
        call.getCallee().getName() = "exec" or
        call.getCallee().getName() = "execSync" or
        call.getCallee().getName() = "spawn"
      )
    )
  }
}

from TaintTracking::PathNode source3, TaintTracking::PathNode sink3
where
  source3 instanceof UserInputSource and
  sink3 instanceof CommandSink and
  TaintTracking::localTaint(source3, sink3)
select sink3,
  "R003: User input flows into a shell command."

/**
 * Mongo-style query sink
 */
class MongoQuerySink extends TaintTracking::SinkNode {
  MongoQuerySink() {
    exists(FunctionCall call, Expr arg |
      arg = this.asExpr() and
      call.getArgument(0) = arg and
      (
        call.getCallee().getQualifiedName().matches("%.find") or
        call.getCallee().getQualifiedName().matches("%.findOne") or
        call.getCallee().getQualifiedName().matches("%.updateOne") or
        call.getCallee().getQualifiedName().matches("%.updateMany")
      )
    )
  }
}

from TaintTracking::PathNode source4, TaintTracking::PathNode sink4
where
  source4 instanceof UserInputSource and
  sink4 instanceof MongoQuerySink and
  TaintTracking::localTaint(source4, sink4)
select sink4,
  "R004: User input flows into a Mongo-style query object."

/**
 * Hard-coded JWT secret
 */
from CallExpr call5
where
  call5.getCallee().getQualifiedName().matches("%jwt.sign%") and
  exists(Expr secret |
    secret = call5.getArgument(1) and
    secret instanceof StringLiteral and
    secret.toString().length() > 0
  )
select call5,
  "R005: Hard-coded JWT secret."

/**
 * Weak hash algorithms
 */
from CallExpr call6
where
  call6.getCallee().getQualifiedName().matches("%crypto.createHash%") and
  exists(Expr alg |
    alg = call6.getArgument(0) and
    alg instanceof StringLiteral and
    (
      alg.getStringValue() = "md5" or
      alg.getStringValue() = "sha1"
    )
  )
select call6,
  "R006: Weak hash algorithm used."

/**
 * Math.random used for token/secret
 */
from CallExpr call7
where
  call7.getCallee().getQualifiedName().matches("%Math.random%") and
  exists(Expr e |
    e = call7.getParent() and
    (
      e.toString().matches("%token%") or
      e.toString().matches("%secret%")
    )
  )
select call7,
  "R007: Math.random() used for token/secret generation."

/**
 * TLS verification disabled
 */
from ObjectLiteral obj8, Property p8
where
  p8 = obj8.getAProperty() and
  p8.getName() = "rejectUnauthorized" and
  exists(BooleanLiteral b8 |
    b8 = p8.getValue() and
    b8.getBooleanValue() = false
  )
select obj8,
  "R008: TLS verification disabled (rejectUnauthorized: false)."

/**
 * Possible logging of sensitive data
 */
from CallExpr call9
where
  call9.getCallee().getName() = "log" and
  exists(Expr arg |
    arg = call9.getArgument(0) and
    (
      arg.toString().matches("%password%") or
      arg.toString().matches("%token%") or
      arg.toString().matches("%authorization%")
    )
  )
select call9,
  "R009: Possible logging of sensitive data."

/**
 * Cookie without HttpOnly
 */
from Expr cookie10
where
  cookie10.toString().matches("%res.cookie%") and
  not cookie10.toString().matches("%HttpOnly%")
select cookie10,
  "R010: Cookie set without HttpOnly flag."
