$(document).ready(function () {
    $(function () {
        $('#data-table').dataTable({
            "bJQueryUI": false,
            "bAutoWidth": false,
            "bProcessing": false,
            "bServerSide": true,
            "sAjaxSource": baseUrl + "/users/getuser/format/html",
            "sPaginationType": "full_numbers",
            // "sDom": '<"datatable-header"Cfril>t<"datatable-footer"p>',
            "aLengthMenu": [[10, 25, 50, 100, 200, -1], [10, 25, 50, 100, 200, "Tous"]],
            "iDisplayLength": 10,
            "oLanguage": {
                "sSearch": "_INPUT_",
                "sLengthMenu": "<span>Entrées :</span> _MENU_",
                "oPaginate": { "sFirst": "First", "sLast": "Last", "sNext": ">", "sPrevious": "<" }
            },
            "aoColumns": [
                { "bSortable": true },
                { "bSortable": true },
                { "bSortable": true },
                { "bSortable": false }
            ],
            "order": [],
            "columnDefs": "[ { orderable: false, targets: [0]}]",
            "fnDrawCallback": function (oSettings) {
                // $(".styled, #checkAll").uniform();
                // hackCheckboxUniform();
                $('.tip').tooltip();
                $("#checkAll").closest('.checker > span').removeClass('checked');
                $('.dataTables_filter input').attr("placeholder", "Votre recherche");
                // edit();

                $(".delete").on("click", function () {
                    var id = $(this).attr('id');

                    swal({
                        title: "Voulez-vous vraiment supprimer cet élément?",
                        showCancelButton: true,
                        confirmButtonColor: "#EF5350",
                        confirmButtonText: "Oui",
                        cancelButtonText: "Non",
                        closeOnConfirm: false,
                    },
                        function (isConfirm) {
                            if (isConfirm) {
                                $.ajax({
                                    type: "POST",
                                    url: baseUrl + "/users/delete/format/html",
                                    data: { "id": id },
                                    dataType: "json",
                                    success: function (data) {
                                        swal({
                                            title: "Element suprrimé avec succès",
                                            confirmButtonColor: "#66BB6A",
                                            type: "success"
                                        });

                                        table = $('#data-table').dataTable();
                                        table.fnDraw();
                                    }
                                });
                            }
                        });
                });
            }
        });
    });
});