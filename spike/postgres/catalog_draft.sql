-- Draft per design.md §6.9 (as specified)
SELECT p.oid::regprocedure AS func, l.lanname, p.prosecdef, e.extname
FROM pg_proc p
JOIN pg_language l ON l.oid = p.prolang
LEFT JOIN pg_depend d ON d.classid = 'pg_proc'::regclass AND d.objid = p.oid
                     AND d.refclassid = 'pg_extension'::regclass AND d.deptype = 'e'
LEFT JOIN pg_extension e ON e.oid = d.refobjid
WHERE NOT l.lanpltrusted
  AND l.lanname <> 'internal'
  AND p.oid >= 16384
  AND (e.extname IS NULL OR e.extname <> ALL (:'allow'::text[]))
  AND has_function_privilege(current_user, p.oid, 'EXECUTE')
ORDER BY 1;
