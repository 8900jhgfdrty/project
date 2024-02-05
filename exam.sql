CREATE OR REPLACE PROCEDURE primefactor(p1 integer) IS
    n integer;
BEGIN
    n := p1;  -- Assign the input number to a local variable
    -- Check for the factor 2 separately
    WHILE MOD(n, 2) = 0 LOOP
        DBMS_OUTPUT.PUT_LINE('2,');
        n := n / 2;
    END LOOP;
    -- Check for odd factors starting from 3
    FOR i IN 3..SQRT(n) LOOP
        WHILE MOD(n, i) = 0 LOOP
            DBMS_OUTPUT.PUT_LINE(i || ',');
            n := n / i;
        END LOOP;
    END LOOP;
    -- If n is a prime number greater than 2
    IF n > 2 THEN
        DBMS_OUTPUT.PUT_LINE(n);
    END IF;
END;
/

SET SERVEROUTPUT ON;
EXECUTE primefactor(14);



create table lu as select * from nikovits.emp;
CREATE OR REPLACE PROCEDURE upd_category(p INTEGER) IS
    v_avg_salary NUMBER;
BEGIN
    -- Start a transaction
    SAVEPOINT start_transaction;

    -- Update the salary
    UPDATE lu e
    SET e.sal = e.sal + 
        (SELECT COUNT(*) * 100 
         FROM nikovits.emp emp 
         WHERE emp.deptno = e.deptno)
    WHERE e.empno IN 
        (SELECT empno 
         FROM nikovits.emp 
         JOIN nikovits.sal_cat sc ON e.sal BETWEEN sc.lowest_sal AND sc.highest_sal
         WHERE sc.category = p);

    -- Calculate the new average salary
    SELECT ROUND(AVG(sal), 2) INTO v_avg_salary FROM nikovits.emp;

    -- Print the new average salary
    DBMS_OUTPUT.PUT_LINE(v_avg_salary);

    -- Rollback the changes
    ROLLBACK TO start_transaction;
END;
SET SERVEROUTPUT ON;
EXECUTE upd_category(2);




CREATE OR REPLACE PROCEDURE letter2 IS
    -- Cursor to select employees
    CURSOR emp_cursor IS
        SELECT ename, sal FROM NIKOVITS.EMP;
    
    -- Variables to hold employee data
    v_ename EMP.ENAME%TYPE;
    v_sal EMP.SAL%TYPE;

    -- Function to check for two identical letters in a string
    FUNCTION has_two_identical_letters(str IN VARCHAR2) RETURN BOOLEAN IS
        letter CHAR(1);
    BEGIN
        FOR i IN 1..LENGTH(str)-1 LOOP
            letter := SUBSTR(str, i, 1);
            IF INSTR(SUBSTR(str, i + 1), letter) > 0 THEN
                RETURN TRUE;
            END IF;
        END LOOP;
        RETURN FALSE;
    END has_two_identical_letters;
BEGIN
    -- Open the cursor
    OPEN emp_cursor;
    
    -- Process each employee
    LOOP
        FETCH emp_cursor INTO v_ename, v_sal;
        EXIT WHEN emp_cursor%NOTFOUND;
        
        -- Check conditions and print
        IF has_two_identical_letters(v_ename) AND v_sal > 1200 THEN
            DBMS_OUTPUT.PUT_LINE(v_ename || ' - ' || v_sal);
        END IF;
    END LOOP;
    
    -- Close the cursor
    CLOSE emp_cursor;
END letter2;
/

SET SERVEROUTPUT ON;
EXECUTE letter2;


CREATE OR REPLACE PROCEDURE primes(n IN INTEGER) IS
    TYPE prime_array IS TABLE OF INTEGER INDEX BY PLS_INTEGER;
    primes prime_array;
    total_sum INTEGER := 0;
    last_prime INTEGER;
    primeIndex INTEGER := 0; -- Renamed to 'primeIndex'
    num INTEGER := 2; -- Start checking from the first prime number, which is 2

    -- Function to check if a number is prime
    FUNCTION is_prime(p_num IN INTEGER) RETURN BOOLEAN IS
    BEGIN
        FOR i IN 2 .. TRUNC(SQRT(p_num)) LOOP
            IF p_num MOD i = 0 THEN
                RETURN FALSE;
            END IF;
        END LOOP;
        RETURN TRUE;
    END is_prime;

BEGIN
    WHILE primeIndex < n LOOP
        IF is_prime(num) THEN
            primes(primeIndex) := num;
            total_sum := total_sum + num;
            last_prime := num;
            primeIndex := primeIndex + 1; -- Updated variable name here
        END IF;
        num := num + 1;
    END LOOP;

    DBMS_OUTPUT.PUT_LINE('Last: ' || last_prime || ' -- Total: ' || total_sum);
END primes;
/
SET SERVEROUTPUT ON;
EXECUTE primes(40);


CREATE OR REPLACE FUNCTION day_name(d varchar2) RETURN varchar2 IS
    v_date DATE;
BEGIN
    -- Try to convert the string to a date using different formats
    BEGIN
        v_date := TO_DATE(d, 'yyyy.mm.dd');
        EXCEPTION WHEN OTHERS THEN
            BEGIN
                v_date := TO_DATE(d, 'dd.mm.yyyy');
                EXCEPTION WHEN OTHERS THEN
                    BEGIN
                        v_date := TO_DATE(d, 'mm.yyyy.dd');
                        EXCEPTION WHEN OTHERS THEN
                            RETURN 'wrong format';
                    END;
            END;
    END;

    -- Return the day name
    RETURN TO_CHAR(v_date, 'fmDay', 'NLS_DATE_LANGUAGE=english');
EXCEPTION
    WHEN OTHERS THEN
        RETURN 'wrong format';
END day_name;
/

SELECT day_name('2018.05.01'), 
       day_name('02.05.2018'), 
       day_name('02.1967.03'), 
       day_name('2018.13.13') 
FROM dual;

CREATE OR REPLACE PROCEDURE char_not_in(p_char IN VARCHAR2) IS
    CURSOR people_cursor IS
        WITH RECURSIVE ancestors (person_id, ancestor_id) AS (
            SELECT person_id, ancestor_id
            FROM NIKOVITS.PARENTOF
            UNION ALL
            SELECT p.person_id, a.ancestor_id
            FROM ancestors a
            JOIN NIKOVITS.PARENTOF p ON a.person_id = p.ancestor_id
        )
        SELECT p.name, p.money
        FROM NIKOVITS.PERSON p -- Assuming PERSON table has the 'name' and 'money' fields
        WHERE NOT EXISTS (
            SELECT 1
            FROM ancestors a
            WHERE (p.person_id = a.person_id OR p.person_id = a.ancestor_id)
            AND INSTR(p.name, p_char) > 0
        )
        GROUP BY p.name, p.money
        HAVING SUM(CASE WHEN INSTR(p.name, p_char) > 0 THEN 1 ELSE 0 END) = 0;

    v_name VARCHAR2(100);
    v_money NUMBER;
BEGIN
    OPEN people_cursor;
    LOOP
        FETCH people_cursor INTO v_name, v_money;
        EXIT WHEN people_cursor%NOTFOUND;
        DBMS_OUTPUT.PUT_LINE(v_name || ' - ' || v_money);
    END LOOP;
    CLOSE people_cursor;
END char_not_in;
/






SET SERVEROUTPUT ON;
EXECUTE char_not_in('N');








