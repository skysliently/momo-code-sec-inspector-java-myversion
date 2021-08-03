package com.zcy.zsec.codeinspect.lang;

import com.intellij.codeInspection.AbstractBaseJavaLocalInspectionTool;

public abstract class ZSecBaseLocalInspectionTool extends AbstractBaseJavaLocalInspectionTool {

    public enum VulnElemType {
        ASSIGNMENT_EXPRESSION,
        LOCAL_VARIABLE,
        CLASS_FIELD
    }


}
