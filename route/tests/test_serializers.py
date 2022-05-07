from django.test import TestCase
from route .serializer import ManagerSerializer,MerchandiserSerializer,RouteSerializer
from route.models import Manager, Merchandiser,Address

class ManagerSerializerTest(TestCase):
    def setUp(self):
        self.manager_attributes ={
            'name':'melody',
            'description':' branch manager',
            'phone_number':'+28390129',
            'location':'Narok'
        }
        self.serializer_data ={
            'name':'melody',
            'description':' branch manager',
            'phone_number':'+28390129',
            'location':'Narok'
        }
        self.manager = Manager.objects.create(**self.manager_attributes)
        self.serializer = ManagerSerializer(instance=self.manager)

    def test_contains_expected_fields(self):
        data = self.serializer.data
        self.assertEqual(set(data.keys()),set(['name','description','phone_number','location']))

class MerchandiserSerializerTest(TestCase):
    def setUp(self):
        self.merchandiser_attributes ={
            'username':'melody_towett',
            'phone_number':'089708643',
            'email':'melody@gmail.com',
            'location':'Narok'
        }
        self.serializer_data ={
            'username':'melody_towett',
            'phone_number':'089708643',
            'email':'melody@gmail.com',
            'location':'Narok'
        }
        self.merchandiser = Merchandiser.objects.create(**self.merchandiser_attributes)
        self.serializer = MerchandiserSerializer(instance=self.merchandiser)

    def test_contains_expected_fields(self):
        data = self.serializer.data
        self.assertEqual(set(data.keys()),set(['username','email','phone_number','location']))

class RouteSerializerTest(TestCase):
    def setUp(self):
        self.route_attribute ={
            'city':'Nairobi',
            'location':'Kenya'
        }
        self.serializer_data ={
            'city':'Nairobi',
            'location':'Kenya'
        }
        self.route = Address.objects.create(**self.route_attribute)
        self.serializer = RouteSerializer(instance=self.route)

    def test_contains_expected_fields(self):
        data = self.serializer.data
        self.assertEqual(set(data.keys()),set(['city','location']))

