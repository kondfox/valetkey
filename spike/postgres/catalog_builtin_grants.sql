-- Built-in functions whose ACL was changed after initdb and that current_user can execute
SELECT p.oid::regprocedure AS func, p.proacl
FROM pg_proc p
LEFT JOIN pg_init_privs ip ON ip.classoid = 'pg_proc'::regclass AND ip.objoid = p.oid AND ip.objsubid = 0
WHERE p.oid < 16384
  AND p.proacl IS DISTINCT FROM ip.initprivs
  AND has_function_privilege(current_user, p.oid, 'EXECUTE')
ORDER BY 1;
