/*
 * 复制自MomoBaseFixElementWalkingVisitor
 */
package com.zcy.zsec.codeinspect.lang;

import com.intellij.psi.PsiRecursiveElementWalkingVisitor;

public abstract class ZSecBaseFixElementWalkingVisitor extends PsiRecursiveElementWalkingVisitor {

    private boolean fix = false;

    public boolean isFix() {
        return fix;
    }

    public void setFix(boolean fix) {
        this.fix = fix;
    }
}
