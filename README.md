XXE 实体解析安全修复
====================

题面
----

导入配置的接口支持 XML，结果有人用它把服务器上的文件内容读了出来：文档类型声明扫描只看第一处，嵌套或重复声明被漏掉；外部引用检查只匹配大写 SYSTEM 关键字，小写形式可以绕过；外部引用检查没有覆盖 PUBLIC 标识与参数实体；实体预算按实体条数而不是展开后的长度计算，膨胀攻击可以穿过；安全展开使用递归替换却没有深度上限，自引用实体会导致栈溢出；展开超限时抛出普通异常而不是约定的解析异常，调用方无法区分失败类型；解析入口先解析后校验，解析阶段已经把实体加载进来；清理函数只删除注释不删除处理指令，指令里的内容被保留；策略校验没有检查文档类型声明是否被禁用；批量解析复用展开缓存，后一个文档会命中前一个文档的实体。xxe/parse.py 是核心，tests/test_parse.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式
--------

在仓库根目录执行：

    python -m pytest tests -q

初始失败环境必须恰好为 15 failed，不能出现 collection error、import error 或 syntax error，也不能有 skipped 或 passed。15 个测试都因为桩函数 raise NotImplementedError 而失败。

修复后，同一命令应变为 15 passed。

字段表
------

    方向        安全
    分类        漏洞检测与攻防
    类型        Bugfix
    技术栈      Python 3, pytest
    依赖        无外部依赖

文件
----

    sec-xxe-entity/
      README.md
      conftest.py
      .gitignore
      xxe/__init__.py
      xxe/parse.py
      tests/test_parse.py

约束
----

- tests/test_parse.py 不可修改，只能修改 xxe/parse.py 的实现。
- 只使用 Python 标准库 xml.etree.ElementTree、re 与 pytest，离线、无随机、无第三方依赖。
- 8 个公开函数初始状态都 raise NotImplementedError，15 个测试在修复前全部为红。
- 外部引用一律拒绝，不解析也不访问。
- 实体展开同时受字节预算与深度上限约束，循环引用是受控失败。
- 解析入口必须先完成策略校验，再检查外部引用，最后才解析。
- 清理函数必须同时删除注释与处理指令。
- 批量解析中的每个文档必须使用独立实体状态。
- 实现与测试的容差为 0。
## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

