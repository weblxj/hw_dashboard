		 
function test()
{
		<script src="https://code.jquery.com/jquery-2.1.4.min.js" type="text/javascript"></script>
		<script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.20.1/moment.min.js"></script>
		<script src="https://cdn.bootcss.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
		<script src="https://cdn.bootcss.com/bootstrap-datetimepicker/4.17.47/js/bootstrap-datetimepicker.min.js"></script>	
		<script src="https://rawgithub.com/indrimuska/jquery-editable-select/master/dist/jquery-editable-select.min.js"></script>
		<script>
			var array = new Array();
			var jquery_obj = new Array();
			var oSelect  = document.getElementsByTagName('select');//获得所有的select 
            for(var i=0;i<oSelect.length;i++){ 
				array.push(oSelect[i]); // put all the objects into the array to avoid accessing unexpected memory 
			};

			for ( var i=0; i<array.length;i++)
			{
				var obj = $('#'+array[i].id);
	            $('#'+array[i].id).editableSelect({filter: false});
				jquery_obj[array[i].id] = $(document.getElementById(array[i].id));
				
				//$('#'+array[i].id).datetimepicker();
				//myobj = $("[name='array[i].id']");
				//id = array[i].id;
				document.getElementById(array[i].id).onselect = function() {handle_select(this,jquery_obj)};
				document.getElementById(array[i].id).onclick = function() {handle_click(this,jquery_obj)};
				
			};
			//document.getElementById("task_p0").datetimepicker({format: 'yyyy-mm-dd hh:ii'});

			myname1 = $(document.getElementById('task_p0'));
			myname2 = $("[name='task_p0']");//$('#select1')
			//alert("object-0:"+$(document.getElementById(self.id)).contents);//document.getElementsByName('task_p0')[0]).data);

			function handle_select(self,obj_list) {
            //    alert("当前选项是:"+self.value+" "+self.id);
			// 	if (self.value=="add date")
 			// 	{
			// 		//alert("on show");
			// 		obj_list[self.id].datetimepicker({format: 'yyyy-mm-dd'});
			// 	}else
			// 	{
			// 		//obj_list[self.id].removeEventListener('click', $(this).datetimepicker,true);
			// 		//obj_list[self.id].bind("focusin",function(){ $(this).datepicker(); });
			// 		//obj_list[self.id].detachEvent();				
			// 	}
			};

			function handle_click(self,obj_list) {
				// if (self.value=="add date")
 				// {
				// 	//obj_list[self.id].datetimepicker({autoclose: "true"});
				// 	//obj_list[self.id].detachEvent();//("focusin",function(){ $(this).datepicker(); });
				//  };
			};

		</script>
};
