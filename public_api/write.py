from psycopg2.extensions import connection




def execute_read_query(conn :connection, query):
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()

        return True, result
    
    except Exception as e:
        return False, str(e)
    


def execute_write_query(conn :connection, query):
    try:
        cursor = conn.cursor()
        cursor.execute(query)

        return True
    
    except Exception as e:
        return False




def operator_feedback(pg_helper :connection,
                      new_link_id :int, 
                      decision :int, 
                      feedback :str,
                      authorize_others :bool,
                      grant_feedback_use :bool):
    
    query = "SELECT count(*) FROM new_links WHERE id_ = {};".format(new_link_id)

    ok, res = execute_read_query(pg_helper, query)

    if not ok:
        return {"code": 400, "detail": "Unable to execute the query. Please retry later or contact an administrator at 'contact@bgproutes.io'."}
    
    if not int(res[0][0]):
        return {"code": 400, "detail": "Unable to find new link with ID {} in the database.".format(new_link_id)}
    
    query = "UPDATE new_links SET operator_validation = {}, operator_feedback = '{}', authorize_others = {}, grant_feedback_use = {} WHERE id_ = {};".format(decision, feedback, authorize_others, grant_feedback_use, new_link_id)

    ok = execute_write_query(pg_helper, query)

    if not ok:
        return {"code": 404, "detail": "Unable to add operator feedback to database for now."}
    
    pg_helper.commit()
    
    return {"code": 200, "detail": "Operator feedback correctly added."}

