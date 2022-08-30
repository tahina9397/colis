<?php
class UsersController extends Application_AbstractController
{
    protected $version;

    public function init()
    {
    }

    public function indexAction()
    {
        $this->view->headTitle()->append('Utilisateurs');

        $this->view->inlineScript()->appendFile(THEMES_DEFAULT_URL . 'scripts/users/index.js?v=' . rand(), 'text/javascript');
    }

    public function getuserAction()
    {
        $this->_helper->layout->disableLayout();
        $this->_helper->viewRenderer->setNoRender();

        $aColumns =
            array(
                'u.name', 'u.age', 'u.email'
            );

        /*
	         * Paging
	         */
        $sLimit = "";
        if (isset($_GET['iDisplayStart']) && $_GET['iDisplayLength'] != '-1') {
            $sLimit = "LIMIT " . intval($_GET['iDisplayStart']) . ", " . intval($_GET['iDisplayLength']);
        }

        /*
	         * Ordering
	         */
        $sOrder = "";
        if (isset($_GET['iSortCol_0'])) {
            $sOrder = "ORDER BY  ";
            for ($i = 0; $i < intval($_GET['iSortingCols']); $i++) {
                if ($_GET['bSortable_' . intval($_GET['iSortCol_' . $i])] == "true") {
                    $sOrder .= $aColumns[intval($_GET['iSortCol_' . $i])] . " " . ($_GET['sSortDir_0'] === 'asc' ? 'ASC' : 'DESC') . ", ";
                }
            }

            $sOrder = substr_replace($sOrder, "", -2);
            if ($sOrder == "ORDER BY") {
                $sOrder = "";
            }
        }

        /*
	         * Filtering
	         */
        $sWhere = "";
        $sWhereParams = array();
        if (isset($_GET['sSearch']) && $_GET['sSearch'] != "") {
            $like1 = $_GET['sSearch'];
            $sWhere = "WHERE (";
            for ($i = 0; $i < count($aColumns); $i++) {
                $sWhere .= $aColumns[$i] . " LIKE :like1 OR ";
            }

            $sWhereParams[":like1"] = "%" . $like1 . "%";

            $sWhere = substr_replace($sWhere, "", -3);
            $sWhere .= ')';
        }

        /* Individual column filtering */
        for ($i = 0; $i < count($aColumns); $i++) {
            if (isset($_GET['bSearchable_' . $i]) && $_GET['bSearchable_' . $i] == "true" && $_GET['sSearch_' . $i] != '') {
                if ($sWhere == "") {
                    $sWhere = "WHERE ";
                } else {
                    $sWhere .= " AND ";
                }

                $sWhere .= $aColumns[$i] . " LIKE :like2_$i ";
                $sWhereParams[":like2_$i"] = "%" . $_GET['sSearch_' . $i] . "%";
            }
        }

        /*
		 * SQL queries
		 * Get data to display
		 */
        $sQuery = "
			SELECT 
				SQL_CALC_FOUND_ROWS u.id
				,u.*
			FROM " . TABLE_PREFIX . "users u
			$sWhere
			$sOrder
			$sLimit
		";

        // echo "<pre>" ;
        // print_r($sQuery);
        // echo "</pre>" ;
        // die() ;

        $rResult        = Application_Model_Global::pquery($sQuery, $sWhereParams);
        $total          = Application_Model_Global::pquery("SELECT FOUND_ROWS()", array());
        $iFilteredTotal = $total[0]['FOUND_ROWS()'];
        $iTotal = $total[0]['FOUND_ROWS()'];

        /*
		 * Output
		 */
        $output = array(
            "sEcho"                => intval($_GET['sEcho']),
            "iTotalRecords"        => $iTotal,
            "iTotalDisplayRecords" => $iFilteredTotal,
            "aaData"               => array()
        );

        if (!empty($rResult)) {
            foreach ($rResult as $k => $item) {
                $row = array();
                $id = $item['id'];

                // $row[] = '<input class="" type="checkbox" value="'.$id.'" name="checked[]">' ;

                $row[] = $item['name'];
                $row[] = $item['age'];
                $row[] = $item['email'];

                $url_edit = $this->view->baseUrl() . "/users/modify/do/edit/id/" . $id;

                $actions = '
		 	 		<a href="' . $url_edit . '" class="btn tip" data-toggle="tooltip" data-original-title="Modifier"><i class="icon-pencil" aria-hidden="true"></i>
		            </a>
	                <a class="btn btn-danger delete tip" id="' . $id . '"  data-toggle="tooltip" data-original-title="Supprimer"><i class="icon-trash" aria-hidden="true"></i>
		            </a>
		 	 	';

                $row[] = $actions;

                $output['aaData'][] = $row;
            }
        }

        echo json_encode($output);
    }

    public function modifyAction()
    {
        $do = $this->_getParam("do");

        ($do == "add") ? $this->view->headTitle()->append('Ajout nouvel utilisateur') :
            $this->view->headTitle()->append('Modication utilisateur');

        $form = new Application_Form_MyForm(array("id" => (int)$this->_getParam("id")));
        $this->view->form = $form;
    }

    public function updatuserAction()
    {
        $this->_helper->layout->disableLayout();
        $this->_helper->viewRenderer->setNoRender();

        $id = (int)$this->_getParam("id");
        $name = $this->_getParam("name");
        $age = (int)$this->_getParam("age");
        $email = $this->_getParam("email");

        $data_user = array(
            "name" => $name, "age" => $age, "email" => $email
        );

        if ($id) {
            Application_Model_Global::pupdate(TABLE_PREFIX . "users", $data_user, "id=:id", array(":id" => $id));
            $res["msg"] = "MAJ";
        } else {
            Application_Model_Global::insert(TABLE_PREFIX . "users", $data_user, "id=:id");
            $res["msg"] = "Ajout";
        }

        $res["state"] = "success";

        echo Zend_Json::encode($res);
    }

    public function deleteAction()
    {
        $this->_helper->layout->disableLayout();
        $this->_helper->viewRenderer->setNoRender();

        $id = (int)$this->_getParam("id");

        if ($id) {
            Application_Model_Global::pdelete(TABLE_PREFIX . "users", "id=:id", array(":id" => $id));
            $res["msg"] = "Suppression ok";
        }

        $res["state"] = "success";

        echo Zend_Json::encode($res);
    }
}
