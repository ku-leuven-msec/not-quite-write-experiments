/**
 * @name Unsafe load of data pointer
 * @kind path-problem
 * @problem.severity warning
 * @id cpp/example/unsafe-dataptr-load
 */

import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.dataflow.new.TaintTracking


predicate isOfAddressType(Type t) {
    t.getUnspecifiedType() instanceof PointerType
    or t.getUnspecifiedType() instanceof ReferenceType
}

predicate isPointerOrStructContainingPtr(Type type) {
    isOfAddressType(type)
    or exists(Field f | f.getDeclaringType().getUnspecifiedType() = type.getUnspecifiedType() 
                and isOfAddressType(f.getType())
    )
}

predicate isUnsafePointerRead(Expr e) {
    (e instanceof ArrayExpr or e instanceof PointerDereferenceExpr)
        // and not e.(ArrayExpr).getArrayOffset() instanceof Literal
    and isPointerOrStructContainingPtr(e.getActualType())
    // and not exists (Loop l | l = e.getEnclosingElement+())
}

predicate isPtrOperandOfWrite(Expr e) {
    exists(VariableAccess va | 
        va instanceof PointerFieldAccess or va instanceof ReferenceFieldAccess or va instanceof ImplicitThisFieldAccess |
        va.isModified() and va.getQualifier() = e
    )
    or 
    exists (ArrayExpr ae | ae.isModified() and ae.getArrayBase() = e)
    or 
    exists (Assignment a | 
        exists (PointerDereferenceExpr pde | pde = a.getLValue() | pde.getOperand() = e)
    )
}


module UnsafeReadToWriteConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node node) {
        // isCallToMalloc(node.asExpr())
        isUnsafePointerRead(node.asExpr())
    }

    predicate isSink(DataFlow::Node node) {
        isPtrOperandOfWrite(node.asExpr())
    }
}

module UnsafeReadToWriteFlow = DataFlow::Global<UnsafeReadToWriteConfig>;
import UnsafeReadToWriteFlow::PathGraph

from UnsafeReadToWriteFlow::PathNode source, UnsafeReadToWriteFlow::PathNode sink 
where UnsafeReadToWriteFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe flow!"
