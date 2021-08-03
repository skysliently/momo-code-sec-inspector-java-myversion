package com.zcy.zsec.codeinspect.lang.xml.rule;

import com.intellij.codeInspection.LocalQuickFix;
import com.intellij.codeInspection.ProblemDescriptor;
import com.intellij.codeInspection.ProblemHighlightType;
import com.intellij.codeInspection.ProblemsHolder;
import com.intellij.lang.ASTFactory;
import com.intellij.openapi.project.Project;
import com.intellij.psi.*;
import com.intellij.psi.xml.*;
import com.intellij.xml.util.XmlUtil;
import com.zcy.zsec.codeinspect.lang.InspectionBundle;
import com.zcy.zsec.codeinspect.lang.ZSecBaseLocalInspectionTool;
import com.zcy.zsec.util.SQLi;
import com.zcy.zsec.util.Str;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

import static com.zcy.zsec.util.SQLi.*;

/**
 * 1004: Mybatis XML SQL注入漏洞
 *
 * Mybatis XML Mapper SQL语句，使用${}方式插入的变量可能存在SQL注入的风险
 */
public class MybatisXmlSQLi extends ZSecBaseLocalInspectionTool {

    public static final String MESSAGE = InspectionBundle.message("mybatis.xml.sqli.msg");
//    public static final String MESSAGE = "ZSec: SQL Injection Risk";
    private static final String QUICK_FIX_NAME = InspectionBundle.message("mybatis.xml.sqli.fix");

    protected static final Set<String> ignoreVarName =
            new HashSet<>(Arrays.asList("pageSize"));
    protected static final Set<String> warningVarName =
            new HashSet<>(Arrays.asList("order by","orderby"));
    protected static final Set<String> orderByVarName =
            new HashSet<>(Arrays.asList("order by","orderby"));

    private final MybatisXmlSQLiQuickFix mybatisXmlSQLiQuickFix = new MybatisXmlSQLiQuickFix();

    @NotNull
    @Override
    public PsiElementVisitor buildVisitor(@NotNull ProblemsHolder holder, boolean isOnTheFly) {
        return new XmlElementVisitor() {
//            XML 文字内容触发器；标签内的文字内容
            @Override
            public void visitXmlText(XmlText text) {
//                最外层以及sql、mapper标签不进行检测
                if (text.getParentTag() != null &&
                        ("sql".equals(text.getParentTag().getName()) || "mapper".equals(text.getParentTag().getName()) )
                ) return;

                XmlDocument document = XmlUtil.getContainingFile(text).getDocument();
                if (document == null) return;

                String dtd = XmlUtil.getDtdUri(document);
//                判断是否是mybatis配置文件
                if (dtd == null || !(dtd.contains("mybatis.org") && dtd.contains("mapper.dtd"))) return;

                String _text = text.getValue();
                if (_text.isEmpty() || !_text.contains("${")) return;

                Matcher matcher = dollarVarPattern.matcher(_text);
                int offset = 0;
                while (matcher.find(offset)) {
                    String prefix = _text.substring(0, matcher.start());
                    String var    = matcher.group(1);
                    String suffix = _text.substring(matcher.end());

                    if (!ignorePosition(prefix, var, suffix) && orderByPosition(prefix, var, suffix)) {
                        holder.registerProblem(text, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
//                        holder.registerProblem(text, MESSAGE, ProblemHighlightType.WARNING);
                        break;
                    }
//                    判断是否在ignore列表中，并判断此处是否有注入风险
                    if (!ignorePosition(prefix, var, suffix) && SQLi.hasVulOnSQLJoinStr(prefix, var, suffix)) {
                        holder.registerProblem(text, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING, mybatisXmlSQLiQuickFix);
//                        holder.registerProblem(text, MESSAGE, ProblemHighlightType.GENERIC_ERROR_OR_WARNING);
                        break;
                    }
                    offset = matcher.end();
                }
            }
        };
    }

//    保留忽略逻辑，忽略内容待定
    private static boolean ignorePosition(String prefix, String var, String suffix) {
//        return MybatisXmlSQLi.ignoreVarName.contains(var) || var.startsWith("ew.");
        return MybatisXmlSQLi.ignoreVarName.contains(var.toLowerCase());
    }

//    区分部分关键字
    private static boolean warningPosition(String prefix, String var, String suffix) {
        return warningVarName.contains(var.toLowerCase());
    }

//    对order by 进行单独检测
    private static boolean orderByPosition(String prefix, String var, String suffix) {
        List<String> fragments = Arrays.stream(prefix.split("[\\s|(]+"))
                .map(String::trim)
                .filter(item -> !item.isEmpty())
                .collect(Collectors.toList());
        String checkStr = fragments.get(fragments.size()-2) + fragments.get(fragments.size()-1);
        return orderByVarName.contains(checkStr.toLowerCase());
    }

    public static class MybatisXmlSQLiQuickFix implements LocalQuickFix {

        @Override
        public @Nls(capitalization = Nls.Capitalization.Sentence) @NotNull String getFamilyName() {
            return QUICK_FIX_NAME;
        }

        @Override
        public void applyFix(@NotNull Project project, @NotNull ProblemDescriptor descriptor) {
            // elem must be XmlText type
            fixXmlText((XmlText)descriptor.getPsiElement(), 0);
        }

        private void fixXmlText(XmlText xmlText, int offset) {
            String v = xmlText.getValue();
            Matcher m = dollarVarPattern.matcher(v);
            while(m.find(offset)) {
                String prefix = v.substring(0, m.start());
                String suffix = v.substring(m.end());
                String var    = m.group(1);

//                找到需要修复的问题所在的位置
                if (ignorePosition(prefix, var, suffix) || !SQLi.hasVulOnSQLJoinStr(prefix, var, suffix)) {
                    offset = m.end();
                    continue;
                }

                if (whereInEndPattern.matcher(prefix).find()) {
                    // where in 型
                    if (Str.rtrim(prefix).endsWith("(") && Str.ltrim(suffix).startsWith(")")) {
                        prefix = Str.rtrim(prefix).substring(0, prefix.length()-1);
                        suffix = Str.ltrim(suffix).substring(1);
                    }
                    XmlTag parent  = xmlText.getParentTag();
                    if (parent != null) {
                        // 0. 保证文本结构，提取上文尾部换行符
                        PsiElement lastElem = xmlText.getLastChild();
                        PsiWhiteSpace lastWhiteSpace;
                        if (lastElem instanceof PsiWhiteSpace) {
                            lastWhiteSpace = (PsiWhiteSpace)lastElem;
                        } else {
                            lastWhiteSpace = (PsiWhiteSpace) PsiParserFacade.SERVICE.getInstance(xmlText.getProject()).createWhiteSpaceFromText("\n");
                        }
                        // 1.先用前缀替换存在问题的文本
                        xmlText.setValue(prefix + lastWhiteSpace.getText());

                        // 2.向后添加foreach标签块
                        XmlTag foreach = createForeachXmlTag(m.group(1), parent, lastWhiteSpace);
                        parent.addAfter(foreach, xmlText);

                        // 3. 补齐尾部文本
                        XmlTag tagFromText = XmlElementFactory.getInstance(xmlText.getProject())
                                .createTagFromText("<a>" + lastWhiteSpace.getText() + suffix + "</a>");
                        XmlText[] textElements = tagFromText.getValue().getTextElements();
                        XmlText suffixXmlText;
                        if (textElements.length == 0) {
                            suffixXmlText = (XmlText) ASTFactory.composite(XmlElementType.XML_TEXT);
                        } else {
                            suffixXmlText = textElements[0];
                        }

                        // 4. 先追加再修正尾部文本
                        parent.add(suffixXmlText);

                        XmlTagChild[] xmlTagChildren = parent.getValue().getChildren();
                        if (xmlTagChildren[xmlTagChildren.length - 1] instanceof XmlText) {
                            fixXmlText((XmlText)xmlTagChildren[xmlTagChildren.length - 1], 0);
                        }
                    } else {
                        fixXmlText(xmlText, m.end());
                    }
                } else if (likeEndPatterh.matcher(prefix).find()) {
                    // like 型
                    String concat = " CONCAT('%', " + m.group().replace('$', '#') + ", '%') ";
                    prefix = StringUtils.stripEnd(prefix, "'\"% \n\r");
                    suffix = StringUtils.stripStart(suffix, "'\"% ");

                    xmlText.removeText(prefix.length(), v.length());
                    xmlText.insertText(concat + suffix, prefix.length());
                    fixXmlText(xmlText, prefix.length() + concat.length());
                } else {
                    if (prefix.trim().endsWith("'") || prefix.trim().endsWith("\"")) {
                        prefix = Str.rtrim(prefix).substring(0, prefix.length()-1);
                        suffix = Str.ltrim(suffix).substring(1);
                    }
                    xmlText.setValue(prefix + "#{" + m.group(1) + "}" + suffix);
                    fixXmlText(xmlText, prefix.length() + m.group().length());
                }
                break;
            }
        }

        private XmlTag createForeachXmlTag(String varName, XmlTag parent, PsiWhiteSpace whiteSpace) {
            XmlTag foreach = parent.createChildTag(
                    "foreach",
                    parent.getNamespace(),
                    String.format("%s#{%sItem}%s", whiteSpace.getText(), varName, whiteSpace.getText()),
                    false);
            foreach.setAttribute("collection", varName);
            foreach.setAttribute("item", varName+"Item");
            foreach.setAttribute("open", "(");
            foreach.setAttribute("separator", ",");
            foreach.setAttribute("close", ")");
            return foreach;
        }

    }

}
