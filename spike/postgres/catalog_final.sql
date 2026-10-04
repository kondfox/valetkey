-- Recommended: untrusted code (incl. user-created `internal`) OR SECURITY DEFINER owned by a privileged role
SELECT p.oid::regprocedure AS func, l.lanname, p.prosecdef, pg_get_userbyid(p.proowner) AS owner, e.extname,
       CASE WHEN NOT l.lanpltrusted THEN 'untrusted-language' ELSE 'privileged-definer' END AS reason
FROM pg_proc p
JOIN pg_language l ON l.oid = p.prolang
LEFT JOIN pg_depend d ON d.classid = 'pg_proc'::regclass AND d.objid = p.oid
                     AND d.refclassid = 'pg_extension'::regclass AND d.deptype = 'e'
LEFT JOIN pg_extension e ON e.oid = d.refobjid
WHERE p.oid >= 16384                                         -- FirstNormalObjectId: skip built-ins
  AND (e.extname IS NULL OR e.extname <> ALL (:'allow'::text[]))
  AND has_function_privilege(current_user, p.oid, 'EXECUTE')
  AND ( NOT l.lanpltrusted                                    -- c, internal, plpython3u, plperlu, ...
        OR ( p.prosecdef AND EXISTS (
               SELECT 1 FROM pg_roles o WHERE o.oid = p.proowner
                 AND ( o.rolsuper
                       OR pg_has_role(o.oid, 'pg_execute_server_program', 'USAGE')
                       OR pg_has_role(o.oid, 'pg_write_server_files', 'USAGE')
                       OR pg_has_role(o.oid, 'pg_read_server_files', 'USAGE')
                       OR pg_has_role(o.oid, 'pg_signal_backend', 'USAGE')))) )
ORDER BY 1;
