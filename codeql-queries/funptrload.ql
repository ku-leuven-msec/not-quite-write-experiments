/**
 * @name Unsafe load of function pointer
 * @kind path-problem
 * @problem.severity warning
 * @id cpp/example/unsafe-funptr-load
 */


import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

predicate isFunPtrOrContainsFunPtr(Type type) {
    type.getUnspecifiedType() instanceof FunctionPointerIshType
    or exists(Field f | f.getDeclaringType().getUnspecifiedType() = type.getUnspecifiedType()
                and f.getType().getUnspecifiedType() instanceof FunctionPointerIshType
    )
}

predicate isPtrOperandOfIndirectFunctionCall(Expr e) {
    exists (ExprCall exprCall | 
        exists (PointerDereferenceExpr ptrDeref | ptrDeref = exprCall.getExpr() | e = ptrDeref.getOperand())
        or
        (not exists (PointerDereferenceExpr ptrDeref | ptrDeref = exprCall.getExpr() | e = ptrDeref.getOperand())
            and exprCall.getExpr() = e)        
    )
}

predicate isUnsafeFuncPtrRead(Expr e) {
    isFunPtrOrContainsFunPtr(e.getActualType()) and
    (e instanceof ArrayExpr or 
        (
            e instanceof PointerDereferenceExpr
            // these dereferences are flukes
            and not exists (ExprCall exprCall | exprCall.getExpr() = e)
        )
    )
    and not exists (SizeofExprOperator sizeofExpr | sizeofExpr.getAChild() = e)
}

module UnsafeReadToCallConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node node) {
        isUnsafeFuncPtrRead(node.asExpr())
    }

    predicate isSink(DataFlow::Node node) {
        isPtrOperandOfIndirectFunctionCall(node.asExpr())
    }
}

module UnsafeReadToCallFlow = DataFlow::Global<UnsafeReadToCallConfig>;
import UnsafeReadToCallFlow::PathGraph

from UnsafeReadToCallFlow::PathNode source, UnsafeReadToCallFlow::PathNode sink  // 8 & 9: using the module directly
where UnsafeReadToCallFlow::flowPath(source, sink)  // 9: using the flowPath from the module 
select sink.getNode(), source, sink, "Unsafe flow!"
