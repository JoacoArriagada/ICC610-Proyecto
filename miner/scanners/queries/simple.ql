/**
 * @name Simple test
 * @kind problem
 * @id test/simple
 * @severity warning
 */
import javascript

from Expr e
where e.getNumLines() > 0
select e, "Expression found"
